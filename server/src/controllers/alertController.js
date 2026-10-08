const Alert = require('../models/Alert');
const Case = require('../models/Case');
const Event = require('../models/Event');
const IOC = require('../models/IOC');
const Endpoint = require('../models/Endpoint');
const Account = require('../models/Account');
const ImpactAssessment = require('../models/ImpactAssessment');
const correlationService = require('../services/correlationService');
const timelineService = require('../services/timelineService');
const attackChainService = require('../services/attackChainService');
const logger = require('../utils/logger');
const { escapeRegex } = require('../utils/sanitize');

async function getAlerts(req, res, next) {
  try {
    const { status, severity, assignedTo, search } = req.query;
    const query = {};

    if (status && typeof status === 'string') query.status = status;
    if (severity && typeof severity === 'string') query.severity = severity;
    if (assignedTo && typeof assignedTo === 'string') query.assignedTo = assignedTo;
    if (search && typeof search === 'string') {
      const safeSearch = escapeRegex(search);
      query.$or = [
        { title: new RegExp(safeSearch, 'i') },
        { alertId: new RegExp(safeSearch, 'i') },
        { description: new RegExp(safeSearch, 'i') },
        { host: new RegExp(safeSearch, 'i') },
        { username: new RegExp(safeSearch, 'i') },
        { sourceIP: new RegExp(safeSearch, 'i') }
      ];
    }

    const alerts = await Alert.find(query)
      .populate('assignedTo', 'fullName username email')
      .populate('ruleId', 'name mitreTechniqueId')
      .populate('caseId', 'caseId title status priority')
      .sort({ createdAt: -1 });

    res.json(alerts);
  } catch (err) {
    next(err);
  }
}

async function getAlertById(req, res, next) {
  try {
    const alert = await Alert.findById(req.params.id)
      .populate('assignedTo', 'fullName username email')
      .populate('ruleId')
      .populate('caseId')
      .populate('matchingEvents');

    if (!alert) return res.status(404).json({ error: 'NotFound', message: 'Alert not found' });
    res.json(alert);
  } catch (err) {
    next(err);
  }
}

async function updateAlert(req, res, next) {
  try {
    // Prevent Mass Assignment (OWASP API3)
    const allowedUpdates = {};
    if (req.body.status !== undefined) allowedUpdates.status = req.body.status;
    if (req.body.severity !== undefined) allowedUpdates.severity = req.body.severity;
    if (req.body.assignedTo !== undefined) allowedUpdates.assignedTo = req.body.assignedTo;
    if (req.body.notes !== undefined) allowedUpdates.notes = req.body.notes;

    const alert = await Alert.findByIdAndUpdate(req.params.id, { $set: allowedUpdates }, { new: true })
      .populate('assignedTo', 'fullName username email');
    if (!alert) return res.status(404).json({ error: 'NotFound', message: 'Alert not found' });
    res.json(alert);
  } catch (err) {
    next(err);
  }
}

async function assignEndpointProfiles(req, res, next) {
  try {
    const alert = await Alert.findById(req.params.id);
    if (!alert) return res.status(404).json({ error: 'NotFound', message: 'Alert not found' });

    const correlated = await correlationService.correlateAlertEntities(alert);
    res.json({
      message: 'Associated endpoints and accounts identified',
      endpoints: correlated.endpoints,
      accounts: correlated.accounts
    });
  } catch (err) {
    next(err);
  }
}

async function createCaseFromAlert(req, res, next) {
  try {
    const alert = await Alert.findById(req.params.id);
    if (!alert) return res.status(404).json({ error: 'NotFound', message: 'Alert not found' });

    if (alert.caseId) {
      const existingCase = await Case.findById(alert.caseId);
      if (existingCase) {
        return res.status(200).json({
          message: 'Case already exists for this alert',
          case: existingCase
        });
      }
    }

    // Generate Case ID
    const year = new Date().getFullYear();
    const caseCount = await Case.countDocuments();
    const seq = String(caseCount + 1).padStart(4, '0');
    const caseId = `CASE-${year}-${seq}`;

    // Correlate entities
    const correlated = await correlationService.correlateAlertEntities(alert);
    const relatedEventIds = Array.from(new Set([
      ...(alert.matchingEvents || []).map(id => id.toString()),
      ...correlated.events.map(e => e._id.toString())
    ]));

    const relatedEvents = await Event.find({ _id: { $in: relatedEventIds } });

    // Link IOCs
    const relatedIocIds = correlated.iocs.map(i => i._id);

    // Create Case
    const newCase = await Case.create({
      caseId,
      title: req.body.title || `Investigation: ${alert.title}`,
      description: req.body.description || alert.description,
      priority: req.body.priority || (alert.severity === 'critical' ? 'critical' : alert.severity === 'high' ? 'high' : 'medium'),
      status: 'investigating',
      phase: 'analysis',
      assignedTo: req.user ? req.user._id : (alert.assignedTo || null),
      alertId: alert._id,
      relatedAlerts: [alert._id],
      relatedEvents: relatedEventIds,
      iocs: relatedIocIds,
      accounts: correlated.accounts.map(a => a._id),
      endpoints: correlated.endpoints.map(e => e._id),
      review: {
        findings: '',
        notes: `Case initialized from Alert ${alert.alertId} (${alert.title})`,
        validatedFlags: { evidence: false, timeline: false, iocs: false }
      }
    });

    // Update Alert to link to case
    alert.caseId = newCase._id;
    alert.status = 'investigating';
    await alert.save();

    // Link IOCs to Case
    if (relatedIocIds.length > 0) {
      await IOC.updateMany({ _id: { $in: relatedIocIds } }, { $set: { caseId: newCase._id } });
    }

    // Build timeline
    await timelineService.buildCaseTimeline(newCase._id, relatedEvents, alert);

    // Build attack chain
    const attackChain = await attackChainService.generateAttackChainForCase(newCase._id, relatedEvents);
    newCase.attackChainId = attackChain._id;

    // Create initial Impact Assessment
    const impact = await ImpactAssessment.create({
      caseId: newCase._id,
      affectedEndpoints: correlated.endpoints.map(e => ({ hostname: e.hostname, severity: e.riskScore > 70 ? 'high' : 'medium' })),
      affectedAccounts: correlated.accounts.map(a => ({ username: a.username, role: a.privilege, sensitivity: a.privilege === 'admin' ? 'critical' : 'medium' })),
      affectedFiles: [
        { path: 'C:\\Windows\\System32\\config\\SAM', sensitivity: 'restricted' },
        { path: 'C:\\Users\\Public\\malware.ps1', sensitivity: 'confidential' }
      ],
      dataExposed: false,
      malwareDetected: 'PowerShell Payload / Remote execution script',
      businessImpact: 'Workstation isolation recommended. Domain controller telemetry stable.',
      autoDetectedIndicators: [
        `Correlated ${correlated.endpoints.length} endpoints`,
        `Correlated ${correlated.accounts.length} targeted accounts`,
        `Extracted ${correlated.iocs.length} indicators of compromise`
      ],
      analystNotes: 'Initial containment underway. No verified data exfiltration detected.',
      confidence: 80,
      assessedBy: req.user ? req.user._id : null
    });
    newCase.impactAssessmentId = impact._id;
    await newCase.save();

    logger.info(`Created case ${newCase.caseId} from alert ${alert.alertId}`);

    res.status(201).json({
      message: 'Case created successfully',
      case: newCase
    });
  } catch (err) {
    logger.error(`Error creating case from alert: ${err.message}`);
    next(err);
  }
}

module.exports = {
  getAlerts,
  getAlertById,
  updateAlert,
  assignEndpointProfiles,
  createCaseFromAlert
};
