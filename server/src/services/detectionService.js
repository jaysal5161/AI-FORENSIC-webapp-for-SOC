/**
 * detectionService.js
 * Evaluates detection rules over event streams, applies thresholding and sequence correlation,
 * and generates deduplicated alerts with MITRE ATT&CK mappings.
 */

const DetectionRule = require('../models/DetectionRule');
const Alert = require('../models/Alert');
const Endpoint = require('../models/Endpoint');
const Account = require('../models/Account');
const logger = require('../utils/logger');

async function generateAlertId() {
  const year = new Date().getFullYear();
  const count = await Alert.countDocuments();
  const seq = String(count + 1).padStart(4, '0');
  return `ALT-${year}-${seq}`;
}

async function runDetectionEngine(newEvents = null) {
  const rules = await DetectionRule.find({ enabled: true });
  if (!rules || rules.length === 0) return [];

  const generatedAlerts = [];
  const now = new Date();

  for (const rule of rules) {
    try {
      // 1. Pattern: Failed Login followed by Successful Login (Credential Access / Initial Access)
      if (rule.condition.patternType === 'failed_then_success_login' || rule.name.toLowerCase().includes('after failure')) {
        const cooldownWindow = new Date(now.getTime() - (rule.condition.windowSeconds || 600) * 1000);
        
        // Find events in memory or recent DB
        const matchEvents = (newEvents || []).filter(e => e.eventType === 'authentication');
        const userGroups = {};

        for (const ev of matchEvents) {
          const key = ev.username || ev.sourceIP;
          if (!key || key === 'SYSTEM') continue;
          if (!userGroups[key]) userGroups[key] = [];
          userGroups[key].push(ev);
        }

        for (const [key, evList] of Object.entries(userGroups)) {
          // Sort chronologically
          evList.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
          const hasFailed = evList.some(e => e.status === 'failed');
          const hasSuccessAfter = evList.some((e, idx) => e.status === 'success' && idx > 0);

          if (hasFailed && hasSuccessAfter) {
            // Check cooldown
            const existingAlert = await Alert.findOne({
              ruleId: rule._id,
              $or: [{ username: key }, { sourceIP: key }],
              createdAt: { $gte: cooldownWindow }
            });

            if (!existingAlert) {
              const alertId = await generateAlertId();
              const matchingIds = evList.map(e => e._id);
              const sampleEvent = evList.find(e => e.status === 'success') || evList[0];

              const alert = await Alert.create({
                alertId,
                title: `${rule.name}: ${key}`,
                description: `${rule.description} detected for ${key}. Multiple failed attempts followed by authenticated session.`,
                severity: rule.severity,
                status: 'new',
                sourceIP: sampleEvent.sourceIP || '',
                host: sampleEvent.host || '',
                username: sampleEvent.username || key,
                eventType: 'authentication',
                count: evList.length,
                matchingEvents: matchingIds,
                rawFile: sampleEvent.rawFile || (newEvents && newEvents[0]?.rawFile) || '',
                ruleId: rule._id,
                ruleName: rule.name,
                mitreTechniqueId: rule.mitreTechniqueId || 'T1078'
              });

              generatedAlerts.push(alert);
              await linkAlertToAssets(alert);
            }
          }
        }
        continue;
      }

      // 2. Standard Threshold & Condition Evaluation
      const filter = {};
      if (rule.condition.eventType) filter.eventType = rule.condition.eventType;
      if (rule.condition.action) filter.action = rule.condition.action;
      if (rule.condition.status) filter.status = rule.condition.status;
      if (rule.condition.source) filter.source = rule.condition.source;

      // Filter given batch
      let matched = (newEvents || []).filter(e => {
        if (filter.eventType && e.eventType !== filter.eventType) return false;
        if (filter.action && e.action !== filter.action) return false;
        if (filter.status && e.status !== filter.status) return false;
        if (filter.source && e.source !== filter.source) return false;
        return true;
      });

      // Group by entity key (sourceIP, username, or host)
      const groups = {};
      for (const ev of matched) {
        const groupKey = ev.sourceIP || ev.username || ev.host || 'UNKNOWN';
        if (!groups[groupKey]) groups[groupKey] = [];
        groups[groupKey].push(ev);
      }

      const threshold = rule.condition.threshold || 1;
      const windowSec = rule.condition.windowSeconds || 300;
      const cooldownDate = new Date(now.getTime() - windowSec * 1000);

      for (const [entityKey, evGroup] of Object.entries(groups)) {
        if (evGroup.length >= threshold) {
          const sample = evGroup[0];
          // Check cooldown
          const existingAlert = await Alert.findOne({
            ruleId: rule._id,
            $or: [
              { sourceIP: entityKey },
              { username: entityKey },
              { host: entityKey }
            ],
            createdAt: { $gte: cooldownDate }
          });

          if (!existingAlert) {
            const alertId = await generateAlertId();
            const alert = await Alert.create({
              alertId,
              title: `${rule.name} [${entityKey}]`,
              description: `${rule.description} (${evGroup.length} occurrences observed).`,
              severity: rule.severity,
              status: 'new',
              sourceIP: sample.sourceIP || '',
              host: sample.host || '',
              username: sample.username || '',
              eventType: sample.eventType || 'other',
              count: evGroup.length,
              matchingEvents: evGroup.map(e => e._id),
              rawFile: sample.rawFile || (newEvents && newEvents[0]?.rawFile) || '',
              ruleId: rule._id,
              ruleName: rule.name,
              mitreTechniqueId: rule.mitreTechniqueId || ''
            });

            generatedAlerts.push(alert);
            await linkAlertToAssets(alert);
          }
        }
      }
    } catch (err) {
      logger.error(`Error evaluating detection rule ${rule.name}: ${err.message}`);
    }
  }

  return generatedAlerts;
}

async function linkAlertToAssets(alert) {
  try {
    if (alert.host) {
      await Endpoint.updateMany(
        { hostname: new RegExp(`^${alert.host}$`, 'i') },
        { $addToSet: { associatedAlerts: alert._id } }
      );
    }
    if (alert.username && alert.username !== 'SYSTEM' && alert.username !== '-') {
      await Account.updateMany(
        { username: new RegExp(`^${alert.username}$`, 'i') },
        { $addToSet: { associatedAlerts: alert._id } }
      );
    }
  } catch (err) {
    logger.error(`Error linking alert ${alert.alertId} to assets: ${err.message}`);
  }
}

module.exports = {
  runDetectionEngine,
  generateAlertId
};
