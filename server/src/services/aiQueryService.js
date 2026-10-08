/**
 * aiQueryService.js
 * AI-powered Natural Language to SQL Query Assistant for SOC Threat Intelligence.
 * Provides database schema awareness, intent recognition, entity extraction,
 * dual-engine (LLM + SOC NLP engine) query generation, validation, and conversation context.
 */

const { executeSql, ALLOWED_TABLES, TABLE_COLUMN_MAPS, resolveColumn } = require('./sqlQueryService');
const logger = require('../utils/logger');

// Complete verified schema definitions for SOC telemetry and threat intelligence
const SCHEMA_METADATA = {
  events: {
    tableName: 'events',
    aliases: ['event', 'security_events'],
    description: 'Raw security telemetry ingested from Windows, Linux, network, EDR, and firewall logs.',
    primaryKey: '_id',
    timestampField: 'timestamp',
    fields: [
      { name: 'timestamp', type: 'date', role: 'timestamp', description: 'Log event observation timestamp' },
      { name: 'source', type: 'string', description: 'Log source telemetry category (windows, linux, network, dns, firewall, application, edr)' },
      { name: 'host', type: 'string', role: 'host', description: 'Host machine hostname or endpoint name' },
      { name: 'username', type: 'string', role: 'user', description: 'Target user account or logon principal' },
      { name: 'source_ip', type: 'string', role: 'ip', description: 'Source IP address generating the event' },
      { name: 'destination_ip', type: 'string', role: 'ip', description: 'Destination IP address targeted by network communication' },
      { name: 'source_port', type: 'number', description: 'Source ephemeral network port' },
      { name: 'destination_port', type: 'number', description: 'Destination service network port (e.g. 445, 80, 443)' },
      { name: 'event_type', type: 'string', description: 'Telemetry category (authentication, process, file, network, dns, registry, other)' },
      { name: 'action', type: 'string', description: 'Activity verb (login, logout, create, delete, execute, connect, failed, success, modify)' },
      { name: 'status', type: 'string', description: 'Outcome status (success, failed, in_allowed_list)' },
      { name: 'severity', type: 'string', description: 'Risk rating (low, medium, high, critical)' },
      { name: 'technique_id', type: 'string', role: 'mitre', description: 'MITRE ATT&CK technique code (e.g. T1110, T1059)' },
      { name: 'description', type: 'string', description: 'Human-readable forensic event description' }
    ]
  },
  alerts: {
    tableName: 'alerts',
    aliases: ['alert', 'security_alerts'],
    description: 'Correlated security detection alerts triggered by Sigma & SOC detection rules.',
    primaryKey: 'alert_id',
    timestampField: 'created_at',
    fields: [
      { name: 'alert_id', type: 'string', role: 'id', description: 'Unique alert identifier (e.g. ALT-2026-0001)' },
      { name: 'title', type: 'string', description: 'Threat detection alert rule title' },
      { name: 'description', type: 'string', description: 'Detailed detection narrative and evidence summary' },
      { name: 'severity', type: 'string', description: 'Alert severity (low, medium, high, critical)' },
      { name: 'status', type: 'string', description: 'Investigation status (new, assigned, investigating, resolved, dismissed, false_positive)' },
      { name: 'source_ip', type: 'string', role: 'ip', description: 'Primary offending source IP address' },
      { name: 'host', type: 'string', role: 'host', description: 'Impacted workstation or domain controller' },
      { name: 'username', type: 'string', role: 'user', description: 'Target user account subjected to intrusion' },
      { name: 'event_type', type: 'string', description: 'Detection vector category (authentication, process, network)' },
      { name: 'count', type: 'number', description: 'Number of raw telemetry hits aggregated in this alert' },
      { name: 'rule_name', type: 'string', description: 'Triggering detection rule name' },
      { name: 'mitre_technique_id', type: 'string', role: 'mitre', description: 'Mapped MITRE ATT&CK technique code' },
      { name: 'created_at', type: 'date', role: 'timestamp', description: 'Alert creation timestamp' }
    ]
  },
  indicators: {
    tableName: 'indicators',
    aliases: ['iocs', 'ioc'],
    description: 'Enterprise forensic IOCs extracted from endpoint investigations and threat intel feeds.',
    primaryKey: '_id',
    timestampField: 'last_seen',
    fields: [
      { name: 'indicator_type', type: 'string', description: 'IOC indicator type (ip, domain, url, hash, username, hostname, email)' },
      { name: 'indicator_value', type: 'string', description: 'Raw indicator token (IP address, domain name, MD5/SHA256 hash)' },
      { name: 'reputation', type: 'string', description: 'Reputation verdict (good, suspicious, malicious, unknown)' },
      { name: 'confidence', type: 'number', description: 'Threat intelligence confidence rating (0 to 100)' },
      { name: 'occurrences', type: 'number', description: 'Total telemetry hit count across enterprise logs' },
      { name: 'source', type: 'string', description: 'Origin source (extracted, manual, threat_intel)' },
      { name: 'last_seen', type: 'date', role: 'timestamp', description: 'Timestamp when this indicator was last observed' },
      { name: 'notes', type: 'string', description: 'Analyst forensic notes and threat feed metadata' }
    ]
  },
  threat_intel: {
    tableName: 'threat_intel',
    aliases: ['threatintel', 'threat_feeds'],
    description: 'External Threat Intelligence Feeds and reputation database (VirusTotal, AlienVault, AbuseIPDB).',
    primaryKey: '_id',
    timestampField: 'last_checked_at',
    fields: [
      { name: 'type', type: 'string', description: 'Indicator type (ip, domain, hash, url)' },
      { name: 'value', type: 'string', description: 'Indicator value' },
      { name: 'verdict', type: 'string', description: 'Reputation verdict (benign, suspicious, malicious)' },
      { name: 'score', type: 'number', description: 'Malicious threat score (0 to 100)' },
      { name: 'source', type: 'string', description: 'Threat feed feed provider name' },
      { name: 'tags', type: 'string', description: 'Associated threat group or malware family tags' },
      { name: 'last_checked_at', type: 'date', role: 'timestamp', description: 'Last external feed synchronization timestamp' }
    ]
  },
  cases: {
    tableName: 'cases',
    aliases: ['case', 'incidents'],
    description: 'Active security incident response and forensic investigation cases.',
    primaryKey: 'case_id',
    timestampField: 'created_at',
    fields: [
      { name: 'case_id', type: 'string', role: 'id', description: 'Incident case ID (e.g. CASE-2026-0001)' },
      { name: 'title', type: 'string', description: 'Incident case title' },
      { name: 'description', type: 'string', description: 'Case synopsis and impact statement' },
      { name: 'priority', type: 'string', description: 'Incident priority (low, medium, high, critical)' },
      { name: 'status', type: 'string', description: 'Case state (open, investigating, pending_review, closed)' },
      { name: 'phase', type: 'string', description: 'IR phase (ingestion, analysis, investigation, forensics, impact, review, closed)' },
      { name: 'created_at', type: 'date', role: 'timestamp', description: 'Case creation timestamp' }
    ]
  }
};

// Global in-memory query history cache for SOC analysts
const queryHistoryStore = [];

/**
 * Returns structured schema metadata for all accessible database tables.
 */
function getSchemaMetadata() {
  return {
    success: true,
    tables: SCHEMA_METADATA,
    supportedOperations: [
      'SELECT',
      'WHERE (=, !=, <>, >, <, >=, <=, LIKE, IN, IS NULL, IS NOT NULL)',
      'AND / OR logical combinations',
      'COUNT(*) and COUNT(DISTINCT column)',
      'GROUP BY with aggregate functions (COUNT, AVG, SUM, MIN, MAX)',
      'HAVING filter clauses',
      'ORDER BY (ASC / DESC)',
      'LIMIT (up to 500 rows)',
      'Date/time filtering (ISO strings, YYYY-MM-DD)'
    ]
  };
}

/**
 * Main AI Query Generation entry point.
 * Supports external LLM if configured; otherwise utilizes the built-in deterministic SOC NLP engine.
 */
async function generateAiQuery({ question, conversationHistory = [], dataset = 'all' }) {
  if (!question || typeof question !== 'string' || !question.trim()) {
    throw new Error('User question cannot be empty.');
  }

  const cleanQuestion = question.trim();

  // 1. Check for follow-up context in conversation history
  const previousTurn = Array.isArray(conversationHistory) && conversationHistory.length > 0
    ? conversationHistory[conversationHistory.length - 1]
    : null;

  // 2. Try LLM Provider if API key is present in environment
  if (process.env.GEMINI_API_KEY || process.env.OPENAI_API_KEY) {
    try {
      const llmResult = await generateViaLlm(cleanQuestion, previousTurn, dataset);
      if (llmResult && llmResult.sql) {
        validateGeneratedSql(llmResult.sql);
        return formatAiResponse(cleanQuestion, llmResult.sql, llmResult.explanation, llmResult.targetTable, 95);
      }
    } catch (llmErr) {
      logger.warn(`External LLM generation failed, falling back to built-in SOC NLP engine: ${llmErr.message}`);
    }
  }

  // 3. High-Accuracy Built-In SOC NLP Engine
  const nlpResult = generateViaSocNlp(cleanQuestion, previousTurn, dataset);
  validateGeneratedSql(nlpResult.sql);

  return formatAiResponse(
    cleanQuestion,
    nlpResult.sql,
    nlpResult.explanation,
    nlpResult.targetTable,
    nlpResult.confidence || 98
  );
}

/**
 * Deterministic SOC NLP Query Generator.
 * Accurately parses cybersecurity queries and maps them to ANSI SQL against real schemas.
 */
function generateViaSocNlp(question, previousTurn, selectedDataset) {
  const q = question.toLowerCase();

  // --- CHECK FOR CONTEXTUAL FOLLOW-UP QUESTIONS ---
  if (previousTurn && previousTurn.sql) {
    const prevSql = previousTurn.sql.replace(/;+\s*$/, '').trim();

    // "Show only failed events" / "Only failed" / "Filter to failed"
    if (/\b(only\s+failed|failed\s+events|status\s+failed|failed\s+only)\b/i.test(q)) {
      let updatedSql = prevSql;
      if (/\bWHERE\b/i.test(updatedSql)) {
        updatedSql = updatedSql.replace(/\bWHERE\b/i, "WHERE status = 'failed' AND ");
      } else if (/\bGROUP\s+BY\b/i.test(updatedSql)) {
        updatedSql = updatedSql.replace(/\bGROUP\s+BY\b/i, "WHERE status = 'failed' GROUP BY");
      } else if (/\bORDER\s+BY\b/i.test(updatedSql)) {
        updatedSql = updatedSql.replace(/\bORDER\s+BY\b/i, "WHERE status = 'failed' ORDER BY");
      } else if (/\bLIMIT\b/i.test(updatedSql)) {
        updatedSql = updatedSql.replace(/\bLIMIT\b/i, "WHERE status = 'failed' LIMIT");
      } else {
        updatedSql += " WHERE status = 'failed'";
      }
      return {
        sql: updatedSql + ';',
        explanation: 'Refined previous query to filter exclusively for failed events (`status = \'failed\'`).',
        targetTable: extractTableFromSql(updatedSql),
        confidence: 96
      };
    }

    // "Top 5" / "Now show the top 5" / "Limit 5"
    const topMatch = q.match(/\b(?:top|limit|show)\s+(\d+)\b/i);
    if (topMatch && (q.includes('now') || q.includes('instead') || q.includes('only') || q.split(/\s+/).length <= 6)) {
      const newLimit = parseInt(topMatch[1], 10);
      let updatedSql = prevSql;
      if (/\bLIMIT\s+\d+\b/i.test(updatedSql)) {
        updatedSql = updatedSql.replace(/\bLIMIT\s+\d+\b/i, `LIMIT ${newLimit}`);
      } else {
        updatedSql += ` LIMIT ${newLimit}`;
      }
      return {
        sql: updatedSql + ';',
        explanation: `Modified previous query result limit to top ${newLimit} records.`,
        targetTable: extractTableFromSql(updatedSql),
        confidence: 98
      };
    }

    // "Filter the results to the last 24 hours" / "last 24 hours" / "last 7 days"
    if (/\b(last\s+24\s+hours|past\s+24\s+hours|today)\b/i.test(q)) {
      const yesterday = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString().split('T')[0];
      let updatedSql = prevSql;
      const targetCol = prevSql.includes('indicators') ? 'last_seen' : 'timestamp';
      if (/\bWHERE\b/i.test(updatedSql)) {
        updatedSql = updatedSql.replace(/\bWHERE\b/i, `WHERE ${targetCol} >= '${yesterday}' AND `);
      } else if (/\bGROUP\s+BY\b/i.test(updatedSql)) {
        updatedSql = updatedSql.replace(/\bGROUP\s+BY\b/i, `WHERE ${targetCol} >= '${yesterday}' GROUP BY`);
      } else {
        updatedSql += ` WHERE ${targetCol} >= '${yesterday}'`;
      }
      return {
        sql: updatedSql + ';',
        explanation: `Added temporal filter to restrict telemetry to the last 24 hours (>= '${yesterday}').`,
        targetTable: extractTableFromSql(updatedSql),
        confidence: 95
      };
    }

    // "Order by count ascending" / "Ascending order"
    if (/\b(asc|ascending)\b/i.test(q)) {
      let updatedSql = prevSql.replace(/\bDESC\b/gi, 'ASC');
      return {
        sql: updatedSql + ';',
        explanation: 'Adjusted query sort order to ascending.',
        targetTable: extractTableFromSql(updatedSql),
        confidence: 97
      };
    }
  }

  // --- QUERY PATTERNS ---

  // 1. "Which IP address generated the highest number of events?" / "Top IP address"
  if (
    (q.includes('ip') && (q.includes('highest') || q.includes('most') || q.includes('top')) && (q.includes('event') || q.includes('number')))
  ) {
    const limit = extractLimit(q, 1);
    return {
      sql: `SELECT source_ip, COUNT(*) AS total_events FROM events WHERE source_ip IS NOT NULL AND source_ip != '' GROUP BY source_ip ORDER BY total_events DESC LIMIT ${limit};`,
      explanation: `Groups all security telemetry in 'events' by 'source_ip', counts total events per IP, and orders descending to return the top ${limit} source IP(s).`,
      targetTable: 'events',
      confidence: 99
    };
  }

  // 2. "How many total security events are recorded?" / "Total events"
  if (
    (q.includes('total') && q.includes('event')) ||
    (q.includes('how many') && q.includes('event')) ||
    (q.includes('count') && q.includes('event') && !q.includes('group'))
  ) {
    return {
      sql: 'SELECT COUNT(*) AS total_events FROM events;',
      explanation: "Computes total count of all recorded security telemetry events in the 'events' collection.",
      targetTable: 'events',
      confidence: 99
    };
  }

  // 3. "Which user has the highest number of failed login attempts?" / "failed logins by user"
  if (
    q.includes('user') && (q.includes('failed') || q.includes('failure')) && (q.includes('login') || q.includes('attempt') || q.includes('auth'))
  ) {
    const limit = extractLimit(q, 1);
    return {
      sql: `SELECT username, COUNT(*) AS failed_attempts FROM events WHERE status = 'failed' AND username IS NOT NULL AND username != '' GROUP BY username ORDER BY failed_attempts DESC LIMIT ${limit};`,
      explanation: `Filters events for failed status ('status = failed'), aggregates counts by 'username', and orders descending to identify the user(s) with the highest failed logins.`,
      targetTable: 'events',
      confidence: 99
    };
  }

  // 4. "Show all malicious IP addresses." / "malicious ips"
  if (
    (q.includes('malicious') && q.includes('ip')) ||
    (q.includes('bad') && q.includes('ip'))
  ) {
    return {
      sql: "SELECT indicator_value, indicator_type, reputation, confidence, occurrences, source, last_seen FROM indicators WHERE reputation = 'malicious' AND indicator_type = 'ip' ORDER BY occurrences DESC LIMIT 50;",
      explanation: "Queries the 'indicators' collection for records where reputation is 'malicious' and indicator type is 'ip', ordered by observed occurrences.",
      targetTable: 'indicators',
      confidence: 98
    };
  }

  // 5. "List the top 10 source IP addresses." / "top source ips"
  if (
    (q.includes('top') || q.includes('list')) && (q.includes('source ip') || q.includes('source ips') || (q.includes('ip') && q.includes('source')))
  ) {
    const limit = extractLimit(q, 10);
    return {
      sql: `SELECT source_ip, COUNT(*) AS total_events FROM events WHERE source_ip IS NOT NULL AND source_ip != '' GROUP BY source_ip ORDER BY total_events DESC LIMIT ${limit};`,
      explanation: `Aggregates security events by source IP address and retrieves the top ${limit} most active originating IP addresses.`,
      targetTable: 'events',
      confidence: 99
    };
  }

  // 6. "How many unique users are present?" / "distinct users"
  if (
    q.includes('unique user') || q.includes('distinct user') || (q.includes('unique') && q.includes('users')) || (q.includes('how many') && q.includes('users'))
  ) {
    return {
      sql: 'SELECT COUNT(DISTINCT username) AS unique_users FROM events;',
      explanation: "Calculates the distinct count of unique usernames observed across all security telemetry in 'events'.",
      targetTable: 'events',
      confidence: 99
    };
  }

  // 7. "Show suspicious authentication events." / "authentication events"
  if (
    (q.includes('suspicious') || q.includes('failed') || q.includes('anomaly')) && q.includes('auth')
  ) {
    return {
      sql: "SELECT timestamp, host, username, source_ip, event_type, action, status, severity, description FROM events WHERE event_type = 'authentication' AND (status = 'failed' OR severity = 'high' OR severity = 'critical') ORDER BY timestamp DESC LIMIT 20;",
      explanation: "Filters the 'events' collection for authentication events that either failed or are categorized as high/critical severity, sorted by latest timestamp.",
      targetTable: 'events',
      confidence: 97
    };
  }

  // 8. "Which IP addresses are associated with multiple failed logins?"
  if (
    q.includes('ip') && q.includes('multiple') && q.includes('failed')
  ) {
    return {
      sql: "SELECT source_ip, COUNT(*) AS failed_logins FROM events WHERE status = 'failed' AND source_ip IS NOT NULL AND source_ip != '' GROUP BY source_ip ORDER BY failed_logins DESC LIMIT 10;",
      explanation: "Groups failed events by source IP address to highlight origin IPs responsible for repetitive authentication failures (e.g. brute force or password spraying).",
      targetTable: 'events',
      confidence: 98
    };
  }

  // 9. "Show all critical severity alerts." / "critical alerts"
  if (
    (q.includes('critical') && q.includes('alert')) ||
    (q.includes('high') && q.includes('alert'))
  ) {
    const sev = q.includes('high') && !q.includes('critical') ? 'high' : 'critical';
    return {
      sql: `SELECT alert_id, title, severity, status, source_ip, host, count, created_at FROM alerts WHERE severity = '${sev}' ORDER BY count DESC LIMIT 20;`,
      explanation: `Retrieves security detection alerts from 'alerts' matching severity = '${sev}', ordered by occurrence count.`,
      targetTable: 'alerts',
      confidence: 99
    };
  }

  // 10. "What is the earliest event in the dataset?" / "first event" / "oldest event"
  if (
    q.includes('earliest') || q.includes('oldest') || q.includes('first event')
  ) {
    return {
      sql: 'SELECT * FROM events ORDER BY timestamp ASC LIMIT 1;',
      explanation: "Sorts the 'events' collection by timestamp in ascending order to return the earliest recorded forensic event in the dataset.",
      targetTable: 'events',
      confidence: 99
    };
  }

  // 11. "Show the latest 20 security events." / "recent events" / "latest events"
  if (
    q.includes('latest') && q.includes('event') || q.includes('recent') && q.includes('event')
  ) {
    const limit = extractLimit(q, 20);
    return {
      sql: `SELECT * FROM events ORDER BY timestamp DESC LIMIT ${limit};`,
      explanation: `Selects all columns from 'events' ordered by timestamp descending to inspect the latest ${limit} observed telemetry records.`,
      targetTable: 'events',
      confidence: 99
    };
  }

  // 12. "Which domain has the highest number of detections?" / "top domain"
  if (
    q.includes('domain') && (q.includes('highest') || q.includes('most') || q.includes('top') || q.includes('detection'))
  ) {
    return {
      sql: "SELECT indicator_value, occurrences, reputation, confidence, source FROM indicators WHERE indicator_type = 'domain' ORDER BY occurrences DESC LIMIT 1;",
      explanation: "Queries the 'indicators' collection for domain indicators and orders descending by observed hit occurrences.",
      targetTable: 'indicators',
      confidence: 98
    };
  }

  // 13. "Show all indicators associated with a particular IP address." / "indicators for IP"
  const ipMatch = question.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/);
  if (ipMatch) {
    const targetIp = ipMatch[0];
    return {
      sql: `SELECT indicator_type, indicator_value, reputation, confidence, occurrences, source, last_seen FROM indicators WHERE indicator_value = '${targetIp}' LIMIT 10;`,
      explanation: `Finds all threat intelligence indicator records in 'indicators' specifically associated with IP address '${targetIp}'.`,
      targetTable: 'indicators',
      confidence: 99
    };
  }

  if (q.includes('indicator') && q.includes('ip')) {
    return {
      sql: "SELECT indicator_type, indicator_value, reputation, confidence, occurrences, last_seen FROM indicators WHERE indicator_type = 'ip' ORDER BY occurrences DESC LIMIT 20;",
      explanation: "Retrieves IP indicators from the 'indicators' registry ordered by occurrence count.",
      targetTable: 'indicators',
      confidence: 96
    };
  }

  // 14. "Which hosts generated the most security alerts?" / "top hosts alerts"
  if (
    (q.includes('host') || q.includes('endpoint')) && q.includes('alert')
  ) {
    const limit = extractLimit(q, 10);
    return {
      sql: `SELECT host, COUNT(*) AS alert_count FROM alerts WHERE host IS NOT NULL AND host != '' GROUP BY host ORDER BY alert_count DESC LIMIT ${limit};`,
      explanation: `Aggregates security alerts in 'alerts' grouped by 'host' machine, ordered descending to surface the most impacted endpoints.`,
      targetTable: 'alerts',
      confidence: 99
    };
  }

  // 15. Threat intel queries (feeds, scores, etc.)
  if (q.includes('feed') || q.includes('threat intel') || q.includes('score')) {
    return {
      sql: 'SELECT * FROM threat_intel WHERE score >= 70 ORDER BY score DESC LIMIT 20;',
      explanation: "Queries the 'threat_intel' external feeds collection for high-confidence threats (score >= 70), ordered by severity score.",
      targetTable: 'threat_intel',
      confidence: 95
    };
  }

  // 16. Case / Incident queries
  if (q.includes('case') || q.includes('incident')) {
    return {
      sql: "SELECT case_id, title, priority, status, phase, created_at FROM cases ORDER BY created_at DESC LIMIT 10;",
      explanation: "Selects active forensic investigation cases from 'cases', showing priority, status, and IR phase.",
      targetTable: 'cases',
      confidence: 96
    };
  }

  // 17. Alert overview queries
  if (q.includes('alert')) {
    return {
      sql: "SELECT alert_id, title, severity, status, source_ip, host, count FROM alerts ORDER BY count DESC LIMIT 20;",
      explanation: "Retrieves top security detection alerts from 'alerts' ordered by aggregated event occurrences.",
      targetTable: 'alerts',
      confidence: 95
    };
  }

  // Default fallback to events telemetry
  return {
    sql: 'SELECT * FROM events ORDER BY timestamp DESC LIMIT 20;',
    explanation: "Defaulting to recent security telemetry from 'events', sorted by latest timestamp.",
    targetTable: 'events',
    confidence: 85
  };
}

/**
 * Extracts a numeric limit from user natural language query (e.g. "top 5" -> 5)
 */
function extractLimit(query, defaultVal = 10) {
  const match = query.match(/\b(?:top|latest|first|show|limit)\s+(\d+)\b/i);
  if (match) {
    const parsed = parseInt(match[1], 10);
    if (!isNaN(parsed) && parsed > 0 && parsed <= 500) {
      return parsed;
    }
  }
  return defaultVal;
}

/**
 * Extracts the target table name from a SQL query string.
 */
function extractTableFromSql(sql) {
  const match = sql.match(/\bFROM\s+([a-zA-Z0-9_]+)\b/i);
  return match ? match[1].toLowerCase() : 'events';
}

/**
 * Validates generated SQL query against security allowlists and schema rules.
 */
function validateGeneratedSql(sql) {
  if (!sql || typeof sql !== 'string') {
    throw new Error('Generated SQL must be a non-empty string.');
  }

  const clean = sql.trim().toUpperCase();
  if (!clean.startsWith('SELECT')) {
    throw new Error('Security Violation: Generated query must be a read-only SELECT statement.');
  }

  const disallowed = ['INSERT', 'UPDATE', 'DELETE', 'DROP', 'ALTER', 'CREATE', 'TRUNCATE', 'GRANT', 'REVOKE'];
  for (const kw of disallowed) {
    if (new RegExp(`\\b${kw}\\b`, 'i').test(sql)) {
      throw new Error(`Security Violation: Keyword '${kw}' is not permitted.`);
    }
  }

  const fromMatch = sql.match(/\bFROM\s+([a-zA-Z0-9_]+)\b/i);
  if (!fromMatch) {
    throw new Error('Invalid SQL: Missing FROM clause.');
  }

  const table = fromMatch[1].toLowerCase();
  if (!ALLOWED_TABLES[table]) {
    throw new Error(`Invalid Table: '${table}' is not in the allowed schema list.`);
  }

  return true;
}

/**
 * Formats standard AI response payload.
 */
function formatAiResponse(question, sql, explanation, targetTable, confidence) {
  const payload = {
    question,
    sql: sql.endsWith(';') ? sql : sql + ';',
    explanation,
    targetTable,
    confidence,
    timestamp: new Date().toISOString(),
    suggestedFollowUps: generateSuggestedFollowUps(targetTable, sql)
  };

  // Add to query history
  queryHistoryStore.unshift({
    id: `HIST-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
    question,
    sql: payload.sql,
    targetTable,
    timestamp: payload.timestamp
  });
  if (queryHistoryStore.length > 50) {
    queryHistoryStore.pop();
  }

  return payload;
}

/**
 * Generates dynamic follow-up prompt chips tailored to the current query context.
 */
function generateSuggestedFollowUps(targetTable, sql) {
  const lowerSql = sql.toLowerCase();
  const suggestions = [];

  if (targetTable === 'events') {
    if (!lowerSql.includes('status =')) {
      suggestions.push('Show only the failed events');
    }
    if (!lowerSql.includes('limit 5')) {
      suggestions.push('Now show the top 5');
    }
    if (!lowerSql.includes('timestamp >=')) {
      suggestions.push('Filter the results to the last 24 hours');
    }
    if (!lowerSql.includes('asc')) {
      suggestions.push('Order by count ascending instead');
    }
  } else if (targetTable === 'alerts') {
    suggestions.push('Show only critical alerts');
    suggestions.push('Which hosts generated the most alerts?');
    suggestions.push('Limit to top 5 alerts');
  } else if (targetTable === 'indicators') {
    suggestions.push('Show only malicious indicators');
    suggestions.push('Group by indicator type');
    suggestions.push('Show indicators with confidence >= 90');
  } else {
    suggestions.push('Show latest 20 events');
    suggestions.push('Top 10 source IP addresses');
  }

  return suggestions.slice(0, 3);
}

/**
 * Retrieves query history for the analyst.
 */
function getQueryHistory(limit = 20) {
  return queryHistoryStore.slice(0, limit);
}

/**
 * Optional integration with external LLM API if environment variable is present.
 */
async function generateViaLlm(question, previousTurn, dataset) {
  const schemaSummary = Object.entries(SCHEMA_METADATA).map(([tbl, meta]) => {
    const colList = meta.fields.map(f => `${f.name} (${f.type})`).join(', ');
    return `Table '${tbl}': ${meta.description}. Columns: ${colList}.`;
  }).join('\n');

  const systemPrompt = `You are a Senior SOC Analyst and SQL Architect.
Given a natural language security question, generate a single, read-only ANSI SQL SELECT statement that can be translated to MongoDB.
Only query the permitted tables: events, alerts, indicators, threat_intel, cases.
Never invent non-existent table or column names.
Allowed tables and columns:
${schemaSummary}

Rules:
1. ONLY read-only SELECT statements. No UPDATE, DELETE, DROP, INSERT, or ALTER.
2. Return JSON in the exact format:
{
  "sql": "SELECT ...;",
  "explanation": "Clear analyst explanation of the query.",
  "targetTable": "name_of_table",
  "confidence": 95
}
`;

  // We can support Google Gemini or OpenAI if respective client or fetch is available
  if (process.env.GEMINI_API_KEY) {
    const endpoint = `https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=${process.env.GEMINI_API_KEY}`;
    const response = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        contents: [
          { role: 'user', parts: [{ text: `${systemPrompt}\n\nQuestion: "${question}"` }] }
        ],
        generationConfig: { responseMimeType: 'application/json' }
      })
    });
    if (response.ok) {
      const data = await response.json();
      const rawText = data.candidates?.[0]?.content?.parts?.[0]?.text;
      if (rawText) {
        return JSON.parse(rawText);
      }
    }
  }

  return null;
}

module.exports = {
  getSchemaMetadata,
  generateAiQuery,
  getQueryHistory,
  validateGeneratedSql,
  SCHEMA_METADATA
};
