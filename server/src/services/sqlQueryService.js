/**
 * sqlQueryService.js
 * High-performance, secure, read-only SQL query engine for the SOC Forensic & Threat Intelligence Platform.
 * Translates ANSI SQL SELECT statements into MongoDB aggregation pipelines and queries.
 * Supports: events, alerts, indicators, threat_intel, cases collections.
 */

const IOC = require('../models/IOC');
const ThreatIntel = require('../models/ThreatIntel');
const Event = require('../models/Event');
const Alert = require('../models/Alert');
const Case = require('../models/Case');
const logger = require('../utils/logger');

// Security allowlist of accessible tables
const ALLOWED_TABLES = {
  // IOC indicators
  indicators: { canonical: 'indicators', model: IOC, defaultSort: { lastSeen: -1 } },
  iocs: { canonical: 'indicators', model: IOC, defaultSort: { lastSeen: -1 } },
  ioc: { canonical: 'indicators', model: IOC, defaultSort: { lastSeen: -1 } },

  // Threat intelligence feeds
  threat_intel: { canonical: 'threat_intel', model: ThreatIntel, defaultSort: { score: -1 } },
  threatintel: { canonical: 'threat_intel', model: ThreatIntel, defaultSort: { score: -1 } },
  threat_feeds: { canonical: 'threat_intel', model: ThreatIntel, defaultSort: { score: -1 } },

  // Security telemetry events
  events: { canonical: 'events', model: Event, defaultSort: { timestamp: -1 } },
  event: { canonical: 'events', model: Event, defaultSort: { timestamp: -1 } },
  security_events: { canonical: 'events', model: Event, defaultSort: { timestamp: -1 } },

  // Security detection alerts
  alerts: { canonical: 'alerts', model: Alert, defaultSort: { createdAt: -1 } },
  alert: { canonical: 'alerts', model: Alert, defaultSort: { createdAt: -1 } },
  security_alerts: { canonical: 'alerts', model: Alert, defaultSort: { createdAt: -1 } },

  // Investigation cases
  cases: { canonical: 'cases', model: Case, defaultSort: { createdAt: -1 } },
  case: { canonical: 'cases', model: Case, defaultSort: { createdAt: -1 } },
  incidents: { canonical: 'cases', model: Case, defaultSort: { createdAt: -1 } }
};

// Column mappings per canonical table
const TABLE_COLUMN_MAPS = {
  indicators: {
    indicator_type: 'type',
    type: 'type',
    indicator_value: 'value',
    indicator: 'value',
    value: 'value',
    reputation: 'reputation',
    verdict: 'reputation',
    confidence: 'confidence',
    confidence_score: 'confidence',
    score: 'confidence',
    source: 'source',
    feed: 'source',
    first_seen: 'firstSeen',
    firstseen: 'firstSeen',
    last_seen: 'lastSeen',
    lastseen: 'lastSeen',
    count: 'count',
    occurrences: 'count',
    hits: 'count',
    case_id: 'caseId',
    caseid: 'caseId',
    notes: 'notes',
    tags: 'tags',
    created_at: 'createdAt',
    updated_at: 'updatedAt',
    id: '_id',
    _id: '_id'
  },
  threat_intel: {
    type: 'type',
    indicator_type: 'type',
    value: 'value',
    indicator: 'value',
    indicator_value: 'value',
    verdict: 'verdict',
    reputation: 'verdict',
    score: 'score',
    confidence: 'score',
    source: 'source',
    feed: 'source',
    tags: 'tags',
    last_checked_at: 'lastCheckedAt',
    lastcheckedat: 'lastCheckedAt',
    last_seen: 'lastCheckedAt',
    timestamp: 'lastCheckedAt',
    created_at: 'createdAt',
    updated_at: 'updatedAt',
    id: '_id',
    _id: '_id'
  },
  events: {
    timestamp: 'timestamp',
    time: 'timestamp',
    date: 'timestamp',
    source: 'source',
    log_source: 'source',
    host: 'host',
    hostname: 'host',
    machine: 'host',
    endpoint: 'host',
    username: 'username',
    user: 'username',
    account: 'username',
    source_ip: 'sourceIP',
    sourceip: 'sourceIP',
    src_ip: 'sourceIP',
    srcip: 'sourceIP',
    ip: 'sourceIP',
    destination_ip: 'destinationIP',
    destinationip: 'destinationIP',
    dest_ip: 'destinationIP',
    dst_ip: 'destinationIP',
    source_port: 'sourcePort',
    sourceport: 'sourcePort',
    src_port: 'sourcePort',
    destination_port: 'destinationPort',
    destinationport: 'destinationPort',
    dest_port: 'destinationPort',
    dst_port: 'destinationPort',
    event_type: 'eventType',
    eventtype: 'eventType',
    type: 'eventType',
    action: 'action',
    status: 'status',
    severity: 'severity',
    technique_id: 'techniqueId',
    techniqueid: 'techniqueId',
    mitre_technique: 'techniqueId',
    mitre: 'techniqueId',
    description: 'description',
    raw_file: 'rawFile',
    rawfile: 'rawFile',
    tags: 'tags',
    created_at: 'createdAt',
    updated_at: 'updatedAt',
    id: '_id',
    _id: '_id'
  },
  alerts: {
    alert_id: 'alertId',
    alertid: 'alertId',
    id: 'alertId',
    _id: '_id',
    title: 'title',
    description: 'description',
    severity: 'severity',
    status: 'status',
    source_ip: 'sourceIP',
    sourceip: 'sourceIP',
    src_ip: 'sourceIP',
    ip: 'sourceIP',
    host: 'host',
    hostname: 'host',
    endpoint: 'host',
    username: 'username',
    user: 'username',
    account: 'username',
    event_type: 'eventType',
    eventtype: 'eventType',
    type: 'eventType',
    count: 'count',
    occurrences: 'count',
    rule_id: 'ruleId',
    rule_name: 'ruleName',
    rulename: 'ruleName',
    rule: 'ruleName',
    mitre_technique_id: 'mitreTechniqueId',
    mitre: 'mitreTechniqueId',
    technique_id: 'mitreTechniqueId',
    case_id: 'caseId',
    caseid: 'caseId',
    created_at: 'createdAt',
    timestamp: 'createdAt',
    updated_at: 'updatedAt'
  },
  cases: {
    case_id: 'caseId',
    caseid: 'caseId',
    id: 'caseId',
    _id: '_id',
    title: 'title',
    description: 'description',
    priority: 'priority',
    severity: 'priority',
    status: 'status',
    phase: 'phase',
    created_at: 'createdAt',
    timestamp: 'createdAt',
    updated_at: 'updatedAt'
  }
};

// Date fields across models for automated string-to-Date conversion
const DATE_FIELDS = new Set([
  'timestamp', 'createdAt', 'updatedAt', 'firstSeen', 'lastSeen', 'lastCheckedAt'
]);

const DISALLOWED_KEYWORDS = [
  'INSERT', 'UPDATE', 'DELETE', 'DROP', 'ALTER', 'CREATE', 'TRUNCATE',
  'GRANT', 'REVOKE', 'REPLACE', 'EXEC', 'EXECUTE', 'SCRIPT', 'ATTACH',
  'DETACH', 'PRAGMA', 'REINDEX', 'VACUUM', 'MERGE', 'UNION', 'INTO'
];

/**
 * Normalizes a column name for the target canonical table using allowlists.
 */
function resolveColumn(colName, canonicalTable = 'indicators') {
  if (!colName || typeof colName !== 'string') return null;
  const clean = colName.trim().toLowerCase().replace(/[`"']/g, '');

  const tableMap = TABLE_COLUMN_MAPS[canonicalTable] || TABLE_COLUMN_MAPS.indicators;
  if (tableMap[clean]) {
    return { field: tableMap[clean], sqlName: clean };
  }

  // Cross-table fallback lookup
  for (const tMap of Object.values(TABLE_COLUMN_MAPS)) {
    if (tMap[clean]) {
      return { field: tMap[clean], sqlName: clean };
    }
  }

  return null;
}

/**
 * Parses WHERE conditions into MongoDB query expressions.
 */
function parseWhereCondition(whereStr, canonicalTable = 'indicators') {
  if (!whereStr || !whereStr.trim()) return {};

  const trimmed = whereStr.trim();

  // Split on top-level OR operators first
  const orParts = splitByOperator(trimmed, 'OR');
  if (orParts.length > 1) {
    return {
      $or: orParts.map(part => parseWhereCondition(part, canonicalTable))
    };
  }

  // Split on top-level AND operators
  const andParts = splitByOperator(trimmed, 'AND');
  if (andParts.length > 1) {
    const andClauses = andParts.map(part => parseWhereCondition(part, canonicalTable));
    const combined = {};
    let hasCollision = false;
    for (const clause of andClauses) {
      for (const key of Object.keys(clause)) {
        if (combined[key] !== undefined) {
          hasCollision = true;
          break;
        }
        combined[key] = clause[key];
      }
      if (hasCollision) break;
    }
    return hasCollision ? { $and: andClauses } : combined;
  }

  // Single condition evaluation
  return parseSinglePredicate(trimmed, canonicalTable);
}

/**
 * Safely splits a string by a logical keyword (AND / OR) outside of quotes and parentheses.
 */
function splitByOperator(str, op) {
  const parts = [];
  let current = '';
  let inQuote = false;
  let quoteChar = '';
  let parenDepth = 0;
  const opPattern = new RegExp(`^\\s+${op}\\s+`, 'i');

  let i = 0;
  while (i < str.length) {
    const char = str[i];

    if ((char === "'" || char === '"') && str[i - 1] !== '\\') {
      if (!inQuote) {
        inQuote = true;
        quoteChar = char;
      } else if (char === quoteChar) {
        inQuote = false;
      }
      current += char;
      i++;
      continue;
    }

    if (!inQuote) {
      if (char === '(') parenDepth++;
      else if (char === ')') parenDepth--;

      if (parenDepth === 0) {
        const remaining = str.slice(i);
        const match = remaining.match(opPattern);
        if (match) {
          parts.push(current.trim());
          current = '';
          i += match[0].length;
          continue;
        }
      }
    }

    current += char;
    i++;
  }

  if (current.trim()) {
    parts.push(current.trim());
  }

  return parts.length > 1 ? parts : [str];
}

/**
 * Parses a single SQL comparison predicate (e.g. `col = 'val'`, `col IN ('a', 'b')`, `col LIKE '%test%'`).
 */
function parseSinglePredicate(predicate, canonicalTable = 'indicators') {
  let text = predicate.trim();

  // Strip wrapping parentheses if fully wrapped
  if (text.startsWith('(') && text.endsWith(')')) {
    text = text.slice(1, -1).trim();
  }

  // 1. IS NULL / IS NOT NULL
  const isNullMatch = text.match(/^([a-zA-Z0-9_]+)\s+IS\s+NULL$/i);
  if (isNullMatch) {
    const col = resolveColumn(isNullMatch[1], canonicalTable);
    if (!col) throw new Error(`Unknown column '${isNullMatch[1]}' in WHERE clause`);
    return { [col.field]: null };
  }

  const isNotNullMatch = text.match(/^([a-zA-Z0-9_]+)\s+IS\s+NOT\s+NULL$/i);
  if (isNotNullMatch) {
    const col = resolveColumn(isNotNullMatch[1], canonicalTable);
    if (!col) throw new Error(`Unknown column '${isNotNullMatch[1]}' in WHERE clause`);
    return { [col.field]: { $ne: null } };
  }

  // 2. IN / NOT IN
  const inMatch = text.match(/^([a-zA-Z0-9_]+)\s+(NOT\s+IN|IN)\s*\(([^)]+)\)$/i);
  if (inMatch) {
    const col = resolveColumn(inMatch[1], canonicalTable);
    if (!col) throw new Error(`Unknown column '${inMatch[1]}' in WHERE clause`);
    const isNotIn = inMatch[2].toUpperCase().includes('NOT');
    const rawItems = inMatch[3].split(',').map(item => cleanLiteral(item.trim(), col.field));
    return { [col.field]: isNotIn ? { $nin: rawItems } : { $in: rawItems } };
  }

  // 3. LIKE / NOT LIKE
  const likeMatch = text.match(/^([a-zA-Z0-9_]+)\s+(NOT\s+LIKE|LIKE)\s+(['"][^'"]*['"])/i);
  if (likeMatch) {
    const col = resolveColumn(likeMatch[1], canonicalTable);
    if (!col) throw new Error(`Unknown column '${likeMatch[1]}' in WHERE clause`);
    const isNotLike = likeMatch[2].toUpperCase().includes('NOT');
    const pattern = cleanLiteral(likeMatch[3], col.field);
    const regexPattern = '^' + String(pattern)
      .replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
      .replace(/%/g, '.*')
      .replace(/_/g, '.') + '$';
    const regexObj = new RegExp(regexPattern, 'i');
    return isNotLike ? { [col.field]: { $not: regexObj } } : { [col.field]: regexObj };
  }

  // 4. Comparison operators: >=, <=, !=, <>, =, >, <
  const compMatch = text.match(/^([a-zA-Z0-9_]+)\s*(=|!=|<>|>=|<=|>|<)\s*(.+)$/);
  if (compMatch) {
    const col = resolveColumn(compMatch[1], canonicalTable);
    if (!col) throw new Error(`Unknown column '${compMatch[1]}' in WHERE clause`);
    const op = compMatch[2];
    const val = cleanLiteral(compMatch[3].trim(), col.field);

    switch (op) {
      case '=':
        return typeof val === 'string'
          ? { [col.field]: { $regex: new RegExp(`^${escapeRegexForExact(val)}$`, 'i') } }
          : { [col.field]: val };
      case '!=':
      case '<>':
        return { [col.field]: { $ne: val } };
      case '>=':
        return { [col.field]: { $gte: val } };
      case '<=':
        return { [col.field]: { $lte: val } };
      case '>':
        return { [col.field]: { $gt: val } };
      case '<':
        return { [col.field]: { $lt: val } };
      default:
        throw new Error(`Unsupported comparison operator '${op}' in WHERE clause`);
    }
  }

  throw new Error(`Invalid or unsupported WHERE condition: "${text}"`);
}

function cleanLiteral(raw, targetField = '') {
  let str = raw.trim();
  // Strip quotes
  if ((str.startsWith("'") && str.endsWith("'")) || (str.startsWith('"') && str.endsWith('"'))) {
    str = str.slice(1, -1);
  }

  // Date parsing for temporal fields
  if (DATE_FIELDS.has(targetField)) {
    const parsedDate = new Date(str);
    if (!isNaN(parsedDate.getTime())) {
      return parsedDate;
    }
  }

  // Number parsing
  if (/^-?\d+(\.\d+)?$/.test(str)) {
    return Number(str);
  }

  // Boolean parsing
  if (str.toLowerCase() === 'true') return true;
  if (str.toLowerCase() === 'false') return false;
  if (str.toLowerCase() === 'null') return null;

  return str;
}

function escapeRegexForExact(str) {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Main SQL query execution function.
 */
async function executeSql(sqlQuery, options = {}) {
  const startTime = Date.now();

  if (!sqlQuery || typeof sqlQuery !== 'string' || !sqlQuery.trim()) {
    throw new Error('SQL query string cannot be empty.');
  }

  let cleaned = sqlQuery.trim();
  cleaned = cleaned.replace(/;+\s*$/, '').trim();

  // 1. Security Check: Block non-SELECT statements (OWASP A01 / API8)
  for (const keyword of DISALLOWED_KEYWORDS) {
    const rx = new RegExp(`\\b${keyword}\\b`, 'i');
    if (rx.test(cleaned)) {
      throw new Error(`Security Violation: Keyword '${keyword}' is prohibited. Only read-only SELECT queries are allowed.`);
    }
  }

  if (!cleaned.toUpperCase().startsWith('SELECT')) {
    throw new Error('Syntax Error: Queries must begin with a SELECT statement.');
  }

  // 2. Extract Top-Level Clauses (SELECT, FROM, WHERE, GROUP BY, HAVING, ORDER BY, LIMIT)
  const clausePattern = /\b(SELECT|FROM|WHERE|GROUP\s+BY|HAVING|ORDER\s+BY|LIMIT)\b/gi;
  const matches = [];
  let m;
  while ((m = clausePattern.exec(cleaned)) !== null) {
    matches.push({ keyword: m[1].toUpperCase().replace(/\s+/g, ' '), index: m.index, length: m[0].length });
  }

  if (matches.length === 0 || matches[0].keyword !== 'SELECT') {
    throw new Error('Syntax Error: Malformed SELECT query.');
  }

  const clauses = {};
  for (let i = 0; i < matches.length; i++) {
    const curr = matches[i];
    const next = matches[i + 1];
    const contentStart = curr.index + curr.length;
    const contentEnd = next ? next.index : cleaned.length;
    clauses[curr.keyword] = cleaned.slice(contentStart, contentEnd).trim();
  }

  if (!clauses.FROM) {
    throw new Error('Syntax Error: Query is missing required FROM clause.');
  }

  // 3. Resolve Target Table
  const rawTable = clauses.FROM.split(/\s+/)[0].replace(/[`"']/g, '').toLowerCase();
  const tableConfig = ALLOWED_TABLES[rawTable];
  if (!tableConfig) {
    const allowedNames = Array.from(new Set(Object.values(ALLOWED_TABLES).map(t => t.canonical))).join(', ');
    throw new Error(`Table '${rawTable}' not found or inaccessible. Allowed tables: ${allowedNames}.`);
  }

  const { canonical, model, defaultSort } = tableConfig;

  // 4. Resolve WHERE Filter
  let matchFilter = {};
  if (clauses.WHERE) {
    matchFilter = parseWhereCondition(clauses.WHERE, canonical);
  }

  // 5. Resolve LIMIT
  let limitNum = 100; // default
  if (clauses.LIMIT) {
    const parsedLimit = parseInt(clauses.LIMIT.trim().split(/\s+/)[0], 10);
    if (!isNaN(parsedLimit) && parsedLimit > 0) {
      limitNum = Math.min(parsedLimit, 500); // Enforce max limit 500
    }
  }

  // 6. Resolve ORDER BY
  let sortObj = null;
  if (clauses['ORDER BY']) {
    sortObj = {};
    const orderParts = clauses['ORDER BY'].split(',').map(p => p.trim());
    for (const part of orderParts) {
      const tokens = part.split(/\s+/);
      const colName = tokens[0].replace(/[`"']/g, '');
      const direction = tokens[1] && tokens[1].toUpperCase() === 'DESC' ? -1 : 1;
      const col = resolveColumn(colName, canonical);
      if (col) {
        sortObj[col.field] = direction;
      } else {
        // May be an aggregate alias (e.g. total_events)
        sortObj[colName] = direction;
      }
    }
  }

  // 7. Parse SELECT expression list
  const selectClause = clauses.SELECT.trim();
  const isDistinct = selectClause.toUpperCase().startsWith('DISTINCT ');
  const rawColumnsStr = isDistinct ? selectClause.slice(9).trim() : selectClause;

  // Check for simple COUNT(*) without group by
  const countStarMatch = rawColumnsStr.match(/^COUNT\s*\(\s*\*\s*\)(\s+AS\s+([a-zA-Z0-9_]+))?$/i);
  if (countStarMatch && !clauses['GROUP BY']) {
    const alias = countStarMatch[2] || 'count';
    const totalCount = await model.countDocuments(matchFilter);
    const duration = Date.now() - startTime;
    return {
      success: true,
      query: cleaned,
      executionTimeMs: duration,
      totalRecords: 1,
      columns: [alias],
      results: [{ [alias]: totalCount }]
    };
  }

  // Check for COUNT(DISTINCT col) without group by
  const countDistinctMatch = rawColumnsStr.match(/^COUNT\s*\(\s*DISTINCT\s+([a-zA-Z0-9_]+)\s*\)(\s+AS\s+([a-zA-Z0-9_]+))?$/i);
  if (countDistinctMatch && !clauses['GROUP BY']) {
    const colName = countDistinctMatch[1];
    const alias = countDistinctMatch[3] || `count_distinct_${colName}`;
    const col = resolveColumn(colName, canonical);
    if (!col) throw new Error(`Unknown column '${colName}' in COUNT(DISTINCT)`);

    const distinctVals = await model.distinct(col.field, matchFilter);
    const duration = Date.now() - startTime;
    return {
      success: true,
      query: cleaned,
      executionTimeMs: duration,
      totalRecords: 1,
      columns: [alias],
      results: [{ [alias]: distinctVals.length }]
    };
  }

  // 8. Handle GROUP BY queries
  if (clauses['GROUP BY']) {
    const groupColName = clauses['GROUP BY'].trim().split(',')[0].trim().replace(/[`"']/g, '');
    const groupCol = resolveColumn(groupColName, canonical);
    if (!groupCol) throw new Error(`Unknown column '${groupColName}' in GROUP BY clause`);

    const pipeline = [];
    if (Object.keys(matchFilter).length > 0) {
      pipeline.push({ $match: matchFilter });
    }

    // Parse aggregates in select list
    const groupStage = { _id: `$${groupCol.field}` };
    const projectStage = { _id: 0, [groupCol.sqlName]: '$_id' };
    const outColumns = [groupCol.sqlName];

    const selectItems = splitSelectItems(rawColumnsStr);
    for (const item of selectItems) {
      const aggMatch = item.match(/^(COUNT|AVG|SUM|MIN|MAX)\s*\(\s*([^)]*)\s*\)(\s+AS\s+([a-zA-Z0-9_]+))?$/i);
      if (aggMatch) {
        const fn = aggMatch[1].toUpperCase();
        const arg = aggMatch[2].trim();
        const alias = aggMatch[4] || `${fn.toLowerCase()}_${arg === '*' ? 'all' : arg}`;

        if (fn === 'COUNT') {
          groupStage[alias] = { $sum: 1 };
          projectStage[alias] = 1;
          outColumns.push(alias);
        } else {
          const argCol = resolveColumn(arg, canonical);
          if (!argCol) throw new Error(`Unknown column '${arg}' in ${fn}()`);
          groupStage[alias] = { [`$${fn.toLowerCase()}`]: `$${argCol.field}` };
          projectStage[alias] = { $round: [`$${alias}`, 2] };
          outColumns.push(alias);
        }
      }
    }

    pipeline.push({ $group: groupStage });
    pipeline.push({ $project: projectStage });

    // Handle HAVING clause if present
    if (clauses.HAVING) {
      const havingMatch = clauses.HAVING.trim().match(/^([a-zA-Z0-9_]+|COUNT\s*\([^)]*\))\s*(=|!=|<>|>=|<=|>|<)\s*(\d+)$/i);
      if (havingMatch) {
        const rawHavingCol = havingMatch[1].trim();
        const op = havingMatch[2];
        const val = Number(havingMatch[3]);
        // Find matching alias
        let targetAlias = rawHavingCol;
        if (/^COUNT/i.test(rawHavingCol)) {
          targetAlias = outColumns.find(c => c !== groupCol.sqlName) || 'total';
        }
        const opMap = { '>': '$gt', '>=': '$gte', '<': '$lt', '<=': '$lte', '=': '$eq', '!=': '$ne', '<>': '$ne' };
        if (opMap[op]) {
          pipeline.push({ $match: { [targetAlias]: { [opMap[op]]: val } } });
        }
      }
    }

    if (sortObj) {
      const sortStage = {};
      for (const [k, v] of Object.entries(sortObj)) {
        if (k === groupCol.field || k === groupCol.sqlName) sortStage[groupCol.sqlName] = v;
        else sortStage[k] = v;
      }
      pipeline.push({ $sort: sortStage });
    } else {
      pipeline.push({ $sort: { [outColumns[outColumns.length - 1]]: -1 } });
    }

    pipeline.push({ $limit: limitNum });

    const results = await model.aggregate(pipeline).option({ maxTimeMS: 5000 });
    const duration = Date.now() - startTime;
    return {
      success: true,
      query: cleaned,
      executionTimeMs: duration,
      totalRecords: results.length,
      columns: outColumns,
      results
    };
  }

  // 9. Handle SELECT DISTINCT column
  if (isDistinct && !rawColumnsStr.includes('*')) {
    const singleColName = rawColumnsStr.trim().split(',')[0].trim().replace(/[`"']/g, '');
    const col = resolveColumn(singleColName, canonical);
    if (!col) throw new Error(`Unknown column '${singleColName}' in DISTINCT clause`);

    const pipeline = [];
    if (Object.keys(matchFilter).length > 0) {
      pipeline.push({ $match: matchFilter });
    }
    pipeline.push({ $group: { _id: `$${col.field}` } });
    pipeline.push({ $project: { _id: 0, [col.sqlName]: '$_id' } });
    pipeline.push({ $sort: { [col.sqlName]: 1 } });
    pipeline.push({ $limit: limitNum });

    const results = await model.aggregate(pipeline).option({ maxTimeMS: 5000 });
    const duration = Date.now() - startTime;
    return {
      success: true,
      query: cleaned,
      executionTimeMs: duration,
      totalRecords: results.length,
      columns: [col.sqlName],
      results
    };
  }

  // 10. Standard SELECT (with projection and filtering)
  const isSelectAll = rawColumnsStr.trim() === '*';
  const outColumns = [];
  const projection = {};

  if (!isSelectAll) {
    const items = splitSelectItems(rawColumnsStr);
    for (const item of items) {
      const aliasMatch = item.match(/^([a-zA-Z0-9_]+)(\s+AS\s+([a-zA-Z0-9_]+))?$/i);
      if (aliasMatch) {
        const colName = aliasMatch[1];
        const alias = aliasMatch[3] || colName;
        const col = resolveColumn(colName, canonical);
        if (!col) throw new Error(`Unknown column '${colName}' in SELECT list`);
        projection[col.field] = 1;
        outColumns.push({ field: col.field, display: alias });
      }
    }
  }

  const queryObj = model.find(matchFilter);
  if (!isSelectAll && Object.keys(projection).length > 0) {
    queryObj.select(projection);
  }
  queryObj.sort(sortObj || defaultSort);
  queryObj.limit(limitNum);
  queryObj.lean();
  queryObj.maxTimeMS(5000);

  const rawDocs = await queryObj.exec();

  // Format output records with friendly display column names
  let displayColumns = [];
  let formattedResults = [];

  if (isSelectAll) {
    switch (canonical) {
      case 'events':
        displayColumns = ['timestamp', 'source_ip', 'destination_ip', 'username', 'host', 'event_type', 'action', 'status', 'severity', 'description'];
        formattedResults = rawDocs.map(doc => ({
          timestamp: doc.timestamp ? new Date(doc.timestamp).toISOString() : '',
          source_ip: doc.sourceIP || '',
          destination_ip: doc.destinationIP || '',
          username: doc.username || '',
          host: doc.host || '',
          event_type: doc.eventType || '',
          action: doc.action || '',
          status: doc.status || '',
          severity: doc.severity || '',
          description: doc.description || ''
        }));
        break;

      case 'alerts':
        displayColumns = ['alert_id', 'title', 'severity', 'status', 'source_ip', 'host', 'username', 'count', 'created_at'];
        formattedResults = rawDocs.map(doc => ({
          alert_id: doc.alertId || '',
          title: doc.title || '',
          severity: doc.severity || '',
          status: doc.status || '',
          source_ip: doc.sourceIP || '',
          host: doc.host || '',
          username: doc.username || '',
          count: doc.count || 1,
          created_at: doc.createdAt ? new Date(doc.createdAt).toISOString() : ''
        }));
        break;

      case 'cases':
        displayColumns = ['case_id', 'title', 'priority', 'status', 'phase', 'created_at'];
        formattedResults = rawDocs.map(doc => ({
          case_id: doc.caseId || '',
          title: doc.title || '',
          priority: doc.priority || '',
          status: doc.status || '',
          phase: doc.phase || '',
          created_at: doc.createdAt ? new Date(doc.createdAt).toISOString() : ''
        }));
        break;

      case 'threat_intel':
        displayColumns = ['type', 'value', 'verdict', 'score', 'source', 'tags', 'lastCheckedAt'];
        formattedResults = rawDocs.map(doc => ({
          type: doc.type,
          value: doc.value,
          verdict: doc.verdict,
          score: doc.score,
          source: doc.source,
          tags: Array.isArray(doc.tags) ? doc.tags.join(', ') : '',
          lastCheckedAt: doc.lastCheckedAt ? new Date(doc.lastCheckedAt).toISOString() : ''
        }));
        break;

      case 'indicators':
      default:
        displayColumns = ['indicator_type', 'indicator_value', 'reputation', 'confidence', 'occurrences', 'source', 'last_seen', 'notes'];
        formattedResults = rawDocs.map(doc => ({
          indicator_type: doc.type,
          indicator_value: doc.value,
          reputation: doc.reputation,
          confidence: doc.confidence,
          occurrences: doc.count,
          source: doc.source,
          last_seen: doc.lastSeen ? new Date(doc.lastSeen).toISOString() : '',
          notes: doc.notes || ''
        }));
        break;
    }
  } else {
    displayColumns = outColumns.map(c => c.display);
    formattedResults = rawDocs.map(doc => {
      const row = {};
      for (const col of outColumns) {
        const val = doc[col.field];
        row[col.display] = val instanceof Date ? val.toISOString() : (val !== undefined ? val : null);
      }
      return row;
    });
  }

  const duration = Date.now() - startTime;
  return {
    success: true,
    query: cleaned,
    executionTimeMs: duration,
    totalRecords: formattedResults.length,
    columns: displayColumns,
    results: formattedResults
  };
}

function splitSelectItems(str) {
  const items = [];
  let current = '';
  let inParen = 0;

  for (let i = 0; i < str.length; i++) {
    const c = str[i];
    if (c === '(') inParen++;
    else if (c === ')') inParen--;

    if (c === ',' && inParen === 0) {
      if (current.trim()) items.push(current.trim());
      current = '';
    } else {
      current += c;
    }
  }
  if (current.trim()) items.push(current.trim());
  return items;
}

module.exports = {
  executeSql,
  resolveColumn,
  ALLOWED_TABLES,
  TABLE_COLUMN_MAPS
};
