const mongoose = require('mongoose');

const alertSchema = new mongoose.Schema({
  alertId: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    index: true
  },
  title: {
    type: String,
    required: true,
    trim: true
  },
  description: {
    type: String,
    required: true
  },
  severity: {
    type: String,
    enum: ['low', 'medium', 'high', 'critical'],
    default: 'medium'
  },
  status: {
    type: String,
    enum: ['new', 'assigned', 'investigating', 'resolved', 'dismissed', 'false_positive'],
    default: 'new'
  },
  sourceIP: {
    type: String,
    default: ''
  },
  host: {
    type: String,
    default: ''
  },
  username: {
    type: String,
    default: ''
  },
  eventType: {
    type: String,
    default: 'other'
  },
  count: {
    type: Number,
    default: 1
  },
  matchingEvents: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Event'
  }],
  rawFile: {
    type: String,
    default: '',
    index: true
  },
  ruleId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'DetectionRule',
    default: null
  },
  ruleName: {
    type: String,
    default: ''
  },
  mitreTechniqueId: {
    type: String,
    default: ''
  },
  caseId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Case',
    default: null
  },
  assignedTo: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    default: null
  },
  createdBy: {
    type: String,
    default: 'DetectionEngine'
  },
  dismissedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    default: null
  }
}, {
  timestamps: true
});

alertSchema.index({ status: 1, severity: 1 });
alertSchema.index({ createdAt: -1 });

module.exports = mongoose.model('Alert', alertSchema);
