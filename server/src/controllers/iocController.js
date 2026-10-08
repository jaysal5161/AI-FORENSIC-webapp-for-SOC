const IOC = require('../models/IOC');
const ThreatIntel = require('../models/ThreatIntel');
const { escapeRegex } = require('../utils/sanitize');

async function getIOCs(req, res, next) {
  try {
    const { type, reputation, caseId, search } = req.query;
    const query = {};

    if (type && typeof type === 'string') query.type = type;
    if (reputation && typeof reputation === 'string') query.reputation = reputation;
    if (caseId && typeof caseId === 'string') query.caseId = caseId;
    if (search && typeof search === 'string') {
      const safeSearch = escapeRegex(search);
      query.$or = [
        { value: new RegExp(safeSearch, 'i') },
        { notes: new RegExp(safeSearch, 'i') }
      ];
    }

    const iocs = await IOC.find(query).sort({ lastSeen: -1 }).limit(200);
    res.json(iocs);
  } catch (err) {
    next(err);
  }
}

async function createIOC(req, res, next) {
  try {
    const { type, value, threatLevel, reputation, notes, caseId, source } = req.body;
    if (!type || !value) {
      return res.status(400).json({ error: 'BadRequest', message: 'IOC type and value are required' });
    }

    const ioc = await IOC.create({
      type,
      value: value.trim(),
      threatLevel: threatLevel || 'medium',
      reputation: reputation || 'suspicious',
      notes: notes || '',
      caseId: caseId || null,
      source: source || 'manual'
    });
    res.status(201).json(ioc);
  } catch (err) {
    next(err);
  }
}

async function updateIOC(req, res, next) {
  try {
    const allowedUpdates = {};
    if (req.body.type !== undefined) allowedUpdates.type = req.body.type;
    if (req.body.value !== undefined) allowedUpdates.value = req.body.value.trim();
    if (req.body.threatLevel !== undefined) allowedUpdates.threatLevel = req.body.threatLevel;
    if (req.body.reputation !== undefined) allowedUpdates.reputation = req.body.reputation;
    if (req.body.notes !== undefined) allowedUpdates.notes = req.body.notes;
    if (req.body.caseId !== undefined) allowedUpdates.caseId = req.body.caseId;

    const ioc = await IOC.findByIdAndUpdate(req.params.id, { $set: allowedUpdates }, { new: true });
    if (!ioc) return res.status(404).json({ error: 'NotFound', message: 'IOC not found' });
    res.json(ioc);
  } catch (err) {
    next(err);
  }
}

async function deleteIOC(req, res, next) {
  try {
    const ioc = await IOC.findByIdAndDelete(req.params.id);
    if (!ioc) return res.status(404).json({ error: 'NotFound', message: 'IOC not found' });
    res.json({ message: 'IOC deleted successfully' });
  } catch (err) {
    next(err);
  }
}

async function lookupIOC(req, res, next) {
  try {
    let { type, value } = req.body;
    if (!value || typeof value !== 'string') {
      return res.status(400).json({ error: 'BadRequest', message: 'Indicator value is required' });
    }

    const cleanVal = value.trim();
    const detectedType = detectIndicatorType(cleanVal);
    const lookupType = (type && type !== 'auto' && type !== 'unknown') ? type.toLowerCase() : detectedType;

    const valRegex = new RegExp(`^${escapeRegex(cleanVal)}$`, 'i');

    // 1. Query Threat Intelligence Feeds
    let ti = null;
    if (lookupType !== 'unknown') {
      ti = await ThreatIntel.findOne({ type: lookupType, value: valRegex });
    }
    if (!ti) {
      // Fallback query across all indicator types by value
      ti = await ThreatIntel.findOne({ value: valRegex });
    }

    // 2. Query Local Telemetry IOCs
    let localIOC = null;
    if (lookupType !== 'unknown') {
      localIOC = await IOC.findOne({ type: lookupType, value: valRegex })
        .populate('caseId', 'caseId title priority status');
    }
    if (!localIOC) {
      localIOC = await IOC.findOne({ value: valRegex })
        .populate('caseId', 'caseId title priority status');
    }

    // 3. Correlate Associated Alerts and Related Cases
    const Alert = require('../models/Alert');
    const Case = require('../models/Case');

    let associatedAlerts = [];
    let relatedCases = [];

    const alertQueries = [
      { sourceIP: valRegex },
      { host: valRegex }
    ];
    if (localIOC && localIOC.relatedEvents && localIOC.relatedEvents.length > 0) {
      alertQueries.push({ matchingEvents: { $in: localIOC.relatedEvents } });
    }

    associatedAlerts = await Alert.find({ $or: alertQueries })
      .select('alertId title severity status createdAt')
      .limit(10);

    const caseQueries = [];
    if (localIOC) {
      caseQueries.push({ iocs: localIOC._id });
      if (localIOC.caseId) {
        caseQueries.push({ _id: localIOC.caseId._id || localIOC.caseId });
      }
    }
    if (associatedAlerts.length > 0) {
      const alertIds = associatedAlerts.map(a => a._id);
      caseQueries.push({ relatedAlerts: { $in: alertIds } });
    }

    if (caseQueries.length > 0) {
      relatedCases = await Case.find({ $or: caseQueries })
        .select('caseId title priority status phase')
        .limit(10);
    }

    // 4. Determine Standardized Verdict
    let verdict = 'no intelligence available';
    let confidence = 0;
    let source = null;

    if (ti) {
      verdict = ti.verdict; // 'malicious' | 'suspicious' | 'benign'
      confidence = ti.score;
      source = ti.source;
    } else if (localIOC) {
      if (localIOC.reputation === 'malicious') verdict = 'malicious';
      else if (localIOC.reputation === 'suspicious') verdict = 'suspicious';
      else if (localIOC.reputation === 'good') verdict = 'benign';
      else verdict = 'unknown';

      confidence = localIOC.confidence;
      source = `Local Telemetry (${localIOC.source})`;
    }

    res.json({
      query: { type: lookupType, value: cleanVal },
      indicator: cleanVal,
      type: (ti ? ti.type : localIOC ? localIOC.type : lookupType),
      verdict, // 'malicious' | 'suspicious' | 'benign' | 'unknown' | 'no intelligence available'
      confidence,
      source,
      firstSeen: localIOC ? localIOC.firstSeen : null,
      lastSeen: localIOC ? localIOC.lastSeen : (ti ? ti.lastCheckedAt : null),
      occurrences: localIOC ? localIOC.count : 0,
      notes: localIOC ? localIOC.notes : '',
      tags: ti ? ti.tags : [],
      threatIntel: ti,
      localIOC,
      associatedAlerts,
      relatedCases
    });
  } catch (err) {
    next(err);
  }
}

function detectIndicatorType(val) {
  if (!val) return 'unknown';
  const str = val.trim();

  // IPv4 check
  const ipv4 = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  if (ipv4.test(str)) return 'ip';

  // IPv6 check
  const ipv6 = /^(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}$|^::1$|^[a-fA-F0-9:]+:+[a-fA-F0-9:]+$/;
  if (ipv6.test(str)) return 'ip';

  // Hashes: MD5 (32), SHA1 (40), SHA256 (64)
  if (/^[a-fA-F0-9]{32}$/.test(str)) return 'hash';
  if (/^[a-fA-F0-9]{40}$/.test(str)) return 'hash';
  if (/^[a-fA-F0-9]{64}$/.test(str)) return 'hash';

  // URLs
  if (/^https?:\/\//i.test(str)) return 'url';

  // Email
  if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(str)) return 'email';

  // Domain
  if (/^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$/.test(str)) {
    return 'domain';
  }

  return 'unknown';
}

const { executeSql } = require('../services/sqlQueryService');
const { generateAiQuery, getSchemaMetadata, getQueryHistory } = require('../services/aiQueryService');
const logger = require('../utils/logger');

async function executeSqlQuery(req, res, next) {
  try {
    const { query } = req.body;
    if (!query || typeof query !== 'string') {
      return res.status(400).json({
        success: false,
        error: 'Query parameter must be a non-empty SQL string.'
      });
    }

    const result = await executeSql(query);

    logger.audit('SQL_QUERY_EXECUTED', {
      actorId: req.user ? req.user._id : null,
      username: req.user ? req.user.username : 'anonymous',
      query,
      executionTimeMs: result.executionTimeMs,
      totalRecords: result.totalRecords,
      ip: req.ip
    });

    res.json(result);
  } catch (err) {
    logger.warn(`SQL Query Error: ${err.message}`, { query: req.body.query });
    res.status(400).json({
      success: false,
      error: err.message,
      executionTimeMs: 0
    });
  }
}

async function generateAiQueryHandler(req, res, next) {
  try {
    const { question, conversationHistory, dataset } = req.body;
    if (!question || typeof question !== 'string' || !question.trim()) {
      return res.status(400).json({
        success: false,
        error: 'Natural language question is required.'
      });
    }

    const aiResult = await generateAiQuery({
      question: question.trim(),
      conversationHistory: Array.isArray(conversationHistory) ? conversationHistory : [],
      dataset: dataset || 'all'
    });

    logger.audit('AI_QUERY_GENERATED', {
      actorId: req.user ? req.user._id : null,
      username: req.user ? req.user.username : 'anonymous',
      question: question.trim(),
      generatedSql: aiResult.sql,
      targetTable: aiResult.targetTable
    });

    res.json({
      success: true,
      ...aiResult
    });
  } catch (err) {
    logger.warn(`AI Query Generation Error: ${err.message}`, { question: req.body?.question });
    res.status(400).json({
      success: false,
      error: err.message
    });
  }
}

async function getSchemaHandler(req, res, next) {
  try {
    const schema = getSchemaMetadata();
    res.json(schema);
  } catch (err) {
    next(err);
  }
}

async function getAiHistoryHandler(req, res, next) {
  try {
    const history = getQueryHistory();
    res.json({ success: true, history });
  } catch (err) {
    next(err);
  }
}

module.exports = {
  getIOCs,
  createIOC,
  updateIOC,
  deleteIOC,
  lookupIOC,
  executeSqlQuery,
  generateAiQueryHandler,
  getSchemaHandler,
  getAiHistoryHandler
};

