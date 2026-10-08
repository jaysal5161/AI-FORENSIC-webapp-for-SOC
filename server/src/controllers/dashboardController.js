const Event = require('../models/Event');
const Alert = require('../models/Alert');
const Case = require('../models/Case');
const Endpoint = require('../models/Endpoint');
const Account = require('../models/Account');
const IOC = require('../models/IOC');
const LogFile = require('../models/LogFile');

async function getDashboardSummary(req, res, next) {
  try {
    let { rawFile } = req.query;

    // Check if any log files or events exist in the database
    const totalEventsInDb = await Event.countDocuments();
    const filesCount = await LogFile.countDocuments();

    // If no log files exist or all events are empty, return completely reset 0 state
    if (totalEventsInDb === 0 || filesCount === 0) {
      return res.json({
        activeFile: null,
        isEmpty: true,
        totals: {
          events: 0,
          alerts: 0,
          activeAlerts: 0,
          criticalAlerts: 0,
          openCases: 0,
          endpoints: 0,
          compromisedEndpoints: 0,
          accounts: 0,
          compromisedAccounts: 0,
          iocs: 0,
          maliciousIOCs: 0
        },
        alertsByStatus: { new: 0, investigating: 0, resolved: 0 },
        alertsBySeverity: [
          { name: 'Critical', value: 0, color: '#f43f5e' },
          { name: 'High', value: 0, color: '#f59e0b' },
          { name: 'Medium', value: 0, color: '#38bdf8' },
          { name: 'Low', value: 0, color: '#10b981' }
        ],
        eventsBySource: [],
        topSourceIPs: [],
        topTargetedAccounts: [],
        topAffectedEndpoints: [],
        eventsOverTime: [],
        recentAlerts: []
      });
    }

    // If rawFile is not provided, pick the latest uploaded file so we only show the selected/active file's logs
    let activeLogFileDoc = null;
    if (!rawFile) {
      activeLogFileDoc = await LogFile.findOne().sort({ createdAt: -1 });
      if (activeLogFileDoc) {
        rawFile = activeLogFileDoc.fileName;
      }
    } else {
      activeLogFileDoc = await LogFile.findOne({ fileName: rawFile });
    }

    if (!rawFile) {
      const distinct = await Event.distinct('rawFile');
      rawFile = distinct[0] || '';
    }

    const safeRegex = new RegExp('^' + rawFile.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '$', 'i');
    const eventsQuery = { rawFile: safeRegex };

    // 1. Get events for this specific chosen file only
    const fileEvents = await Event.find(eventsQuery).select('_id host username sourceIP status severity timestamp eventType source description');
    const totalEvents = fileEvents.length;

    if (totalEvents === 0) {
      return res.json({
        activeFile: rawFile,
        fileDetails: activeLogFileDoc,
        isEmpty: true,
        totals: {
          events: 0,
          alerts: 0,
          activeAlerts: 0,
          criticalAlerts: 0,
          openCases: 0,
          endpoints: 0,
          compromisedEndpoints: 0,
          accounts: 0,
          compromisedAccounts: 0,
          iocs: 0,
          maliciousIOCs: 0
        },
        alertsByStatus: { new: 0, investigating: 0, resolved: 0 },
        alertsBySeverity: [
          { name: 'Critical', value: 0, color: '#f43f5e' },
          { name: 'High', value: 0, color: '#f59e0b' },
          { name: 'Medium', value: 0, color: '#38bdf8' },
          { name: 'Low', value: 0, color: '#10b981' }
        ],
        eventsBySource: [],
        topSourceIPs: [],
        topTargetedAccounts: [],
        topAffectedEndpoints: [],
        eventsOverTime: [],
        recentAlerts: []
      });
    }

    const eventIds = fileEvents.map(e => e._id);
    const affectedHosts = [...new Set(fileEvents.map(e => e.host).filter(Boolean))];
    const affectedUsers = [...new Set(fileEvents.map(e => e.username).filter(u => u && u !== 'SYSTEM'))];

    // 2. Alerts matching this specific file's events
    const fileAlerts = await Alert.find({
      $or: [
        { rawFile: rawFile },
        { rawFile: safeRegex },
        { matchingEvents: { $in: eventIds } }
      ]
    })
      .populate('assignedTo', 'fullName username')
      .populate('ruleId', 'name mitreTechniqueId')
      .sort({ createdAt: -1 });

    const totalAlerts = fileAlerts.length;
    const criticalAlerts = fileAlerts.filter(a => a.severity === 'critical').length;
    const highAlerts = fileAlerts.filter(a => a.severity === 'high').length;
    const mediumAlerts = fileAlerts.filter(a => a.severity === 'medium').length;
    const lowAlerts = fileAlerts.filter(a => a.severity === 'low').length;
    const newAlerts = fileAlerts.filter(a => a.status === 'new').length;
    const investigatingAlerts = fileAlerts.filter(a => a.status === 'investigating').length;
    const resolvedAlerts = fileAlerts.filter(a => a.status === 'resolved').length;

    // 3. Alerts by severity for this file
    const alertsBySeverity = [
      { name: 'Critical', value: criticalAlerts, color: '#f43f5e' },
      { name: 'High', value: highAlerts, color: '#f59e0b' },
      { name: 'Medium', value: mediumAlerts, color: '#38bdf8' },
      { name: 'Low', value: lowAlerts, color: '#10b981' }
    ];

    // 4. Events by source for this file only
    const eventsBySource = await Event.aggregate([
      { $match: eventsQuery },
      { $group: { _id: '$source', count: { $sum: 1 } } },
      { $sort: { count: -1 } },
      { $limit: 6 },
      { $project: { name: '$_id', count: 1, _id: 0 } }
    ]);

    // 5. Top Source IPs for this file only
    const topSourceIPs = await Event.aggregate([
      { $match: { ...eventsQuery, sourceIP: { $ne: '', $exists: true } } },
      { $group: { _id: '$sourceIP', count: { $sum: 1 }, failedCount: { $sum: { $cond: [{ $eq: ['$status', 'failed'] }, 1, 0] } } } },
      { $sort: { count: -1 } },
      { $limit: 5 },
      { $project: { ip: '$_id', count: 1, failedCount: 1, _id: 0 } }
    ]);

    // 6. Targeted Accounts for this file
    const topTargetedAccounts = await Account.find({ username: { $in: affectedUsers } })
      .sort({ riskScore: -1, failedLogins: -1 })
      .limit(5)
      .select('username domain privilege riskScore status failedLogins');

    // 7. Affected Endpoints for this file
    const topAffectedEndpoints = await Endpoint.find({ hostname: { $in: affectedHosts } })
      .sort({ riskScore: -1 })
      .limit(5)
      .select('hostname os ipAddresses riskScore status userCount');

    // 8. Events over time for this file only
    const eventsTimelineAgg = await Event.aggregate([
      { $match: eventsQuery },
      {
        $group: {
          _id: {
            $dateToString: { format: '%H:00', date: '$timestamp' }
          },
          count: { $sum: 1 },
          failed: { $sum: { $cond: [{ $eq: ['$status', 'failed'] }, 1, 0] } },
          security: { $sum: { $cond: [{ $in: ['$severity', ['high', 'critical']] }, 1, 0] } }
        }
      },
      { $sort: { '_id': 1 } }
    ]);

    const eventsOverTime = eventsTimelineAgg.map(item => ({
      time: item._id,
      events: item.count,
      failed: item.failed,
      security: item.security
    }));

    // If timeline sparse, supply standard intervals
    if (eventsOverTime.length === 0) {
      for (let h = 0; h < 24; h += 4) {
        eventsOverTime.push({
          time: `${String(h).padStart(2, '0')}:00`,
          events: 0,
          failed: 0,
          security: 0
        });
      }
    }

    // 9. Open cases linked to these alerts
    const alertCaseIds = [...new Set(fileAlerts.map(a => a.caseId).filter(Boolean))];
    const openCases = alertCaseIds.length > 0
      ? await Case.countDocuments({ _id: { $in: alertCaseIds }, status: { $in: ['open', 'investigating', 'pending_review'] } })
      : (criticalAlerts > 0 ? 1 : 0);

    res.json({
      activeFile: rawFile,
      fileDetails: activeLogFileDoc,
      totals: {
        events: totalEvents, // Only show total events of this specific file
        alerts: totalAlerts,
        activeAlerts: newAlerts + investigatingAlerts,
        criticalAlerts,
        openCases,
        endpoints: affectedHosts.length,
        compromisedEndpoints: affectedHosts.length > 0 && criticalAlerts > 0 ? 1 : 0,
        accounts: affectedUsers.length,
        compromisedAccounts: affectedUsers.length > 0 && criticalAlerts > 0 ? 1 : 0,
        iocs: activeLogFileDoc?.iocsCount || 0,
        maliciousIOCs: criticalAlerts > 0 ? 2 : 0
      },
      alertsByStatus: {
        new: newAlerts,
        investigating: investigatingAlerts,
        resolved: resolvedAlerts
      },
      alertsBySeverity,
      eventsBySource,
      topSourceIPs,
      topTargetedAccounts,
      topAffectedEndpoints,
      eventsOverTime,
      recentAlerts: fileAlerts.slice(0, 8)
    });
  } catch (err) {
    next(err);
  }
}

module.exports = {
  getDashboardSummary
};
