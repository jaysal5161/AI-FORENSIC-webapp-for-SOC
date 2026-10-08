const mongoose = require('mongoose');

const eventSchema = new mongoose.Schema({
  timestamp: {
    type: Date,
    required: true,
    index: true
  },
  source: {
    type: String,
    enum: ['windows', 'linux', 'network', 'dns', 'firewall', 'application', 'cloud', 'edr'],
    required: true,
    default: 'windows'
  },
  host: {
    type: String,
    required: true,
    trim: true,
    index: true
  },
  username: {
    type: String,
    trim: true,
    index: true,
    default: 'SYSTEM'
  },
  sourceIP: {
    type: String,
    trim: true,
    index: true,
    default: ''
  },
  destinationIP: {
    type: String,
    trim: true,
    default: ''
  },
  sourcePort: {
    type: Number,
    default: null
  },
  destinationPort: {
    type: Number,
    default: null
  },
  eventType: {
    type: String,
    enum: ['authentication', 'process', 'file', 'network', 'dns', 'registry', 'other'],
    required: true,
    default: 'other'
  },
  action: {
    type: String,
    enum: ['login', 'logout', 'create', 'delete', 'execute', 'connect', 'failed', 'success', 'modify'],
    required: true,
    default: 'execute'
  },
  status: {
    type: String,
    enum: ['success', 'failed', 'in_allowed_list'],
    required: true,
    default: 'success'
  },
  severity: {
    type: String,
    enum: ['low', 'medium', 'high', 'critical'],
    default: 'low'
  },
  raw: {
    type: mongoose.Schema.Types.Mixed,
    default: {}
  },
  rawFile: {
    type: String,
    default: ''
  },
  techniqueId: {
    type: String,
    trim: true,
    default: ''
  },
  description: {
    type: String,
    required: true,
    trim: true
  },
  tags: {
    type: [String],
    default: []
  }
}, {
  timestamps: true
});

eventSchema.index({ timestamp: -1 });
eventSchema.index({ host: 1, timestamp: -1 });
eventSchema.index({ sourceIP: 1, timestamp: -1 });
eventSchema.index({ username: 1, timestamp: -1 });
eventSchema.index({ rawFile: 1 });

module.exports = mongoose.model('Event', eventSchema);
