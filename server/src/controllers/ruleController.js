const DetectionRule = require('../models/DetectionRule');
const Event = require('../models/Event');
const detectionService = require('../services/detectionService');

async function getRules(req, res, next) {
  try {
    const rules = await DetectionRule.find().sort({ createdAt: -1 });
    res.json(rules);
  } catch (err) {
    next(err);
  }
}

async function getRuleById(req, res, next) {
  try {
    const rule = await DetectionRule.findById(req.params.id);
    if (!rule) return res.status(404).json({ error: 'NotFound', message: 'Detection rule not found' });
    res.json(rule);
  } catch (err) {
    next(err);
  }
}

async function createRule(req, res, next) {
  try {
    if (!req.body.name || !req.body.description) {
      return res.status(400).json({ error: 'ValidationError', message: 'Rule name and description are required' });
    }
    const existing = await DetectionRule.findOne({ name: req.body.name.trim() });
    if (existing) {
      return res.status(400).json({ error: 'DuplicateName', message: `A detection rule named "${req.body.name}" already exists.` });
    }
    const rule = await DetectionRule.create(req.body);
    res.status(201).json(rule);
  } catch (err) {
    if (err.code === 11000) {
      return res.status(400).json({ error: 'DuplicateName', message: 'A detection rule with this name already exists' });
    }
    next(err);
  }
}

async function updateRule(req, res, next) {
  try {
    const rule = await DetectionRule.findById(req.params.id);
    if (!rule) return res.status(404).json({ error: 'NotFound', message: 'Detection rule not found' });

    if (req.body.name !== undefined) {
      const trimmedName = req.body.name.trim();
      if (trimmedName !== rule.name) {
        const duplicate = await DetectionRule.findOne({ name: trimmedName, _id: { $ne: rule._id } });
        if (duplicate) {
          return res.status(400).json({ error: 'DuplicateName', message: `Rule name "${trimmedName}" is already taken.` });
        }
      }
      rule.name = trimmedName;
    }

    if (req.body.description !== undefined) rule.description = req.body.description.trim();
    if (req.body.severity !== undefined) rule.severity = req.body.severity;
    if (req.body.enabled !== undefined) rule.enabled = Boolean(req.body.enabled);
    if (req.body.mitreTechniqueId !== undefined) rule.mitreTechniqueId = req.body.mitreTechniqueId.trim();
    if (req.body.tags !== undefined) rule.tags = req.body.tags;

    if (req.body.condition) {
      const existingCondition = rule.condition ? (rule.condition.toObject ? rule.condition.toObject() : rule.condition) : {};
      rule.condition = {
        ...existingCondition,
        ...req.body.condition
      };
      rule.markModified('condition');
    }

    await rule.save();
    res.json(rule);
  } catch (err) {
    if (err.code === 11000) {
      return res.status(400).json({ error: 'DuplicateName', message: 'A detection rule with this name already exists' });
    }
    next(err);
  }
}

async function deleteRule(req, res, next) {
  try {
    const rule = await DetectionRule.findByIdAndDelete(req.params.id);
    if (!rule) return res.status(404).json({ error: 'NotFound', message: 'Detection rule not found' });
    res.json({ message: 'Rule deleted successfully' });
  } catch (err) {
    next(err);
  }
}

async function runAllRules(req, res, next) {
  try {
    const recentEvents = await Event.find().sort({ timestamp: -1 }).limit(500);
    const alerts = await detectionService.runDetectionEngine(recentEvents);
    res.json({
      message: `Detection engine executed over ${recentEvents.length} events`,
      alertsGenerated: alerts.length,
      alerts
    });
  } catch (err) {
    next(err);
  }
}

module.exports = {
  getRules,
  getRuleById,
  createRule,
  updateRule,
  deleteRule,
  runAllRules
};
