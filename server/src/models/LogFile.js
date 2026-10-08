const mongoose = require('mongoose');

const logFileSchema = new mongoose.Schema({
  fileName: {
    type: String,
    required: true,
    trim: true,
    index: true
  },
  storedName: {
    type: String,
    default: '',
    trim: true
  },
  filePath: {
    type: String,
    default: ''
  },
  fileSize: {
    type: Number,
    default: 0
  },
  mimeType: {
    type: String,
    default: 'text/plain'
  },
  format: {
    type: String,
    enum: ['csv', 'json', 'syslog', 'text', 'other'],
    default: 'text'
  },
  eventsCount: {
    type: Number,
    default: 0
  },
  iocsCount: {
    type: Number,
    default: 0
  },
  alertsCount: {
    type: Number,
    default: 0
  },
  isSaved: {
    type: Boolean,
    default: true
  },
  uploadedBy: {
    type: String,
    default: 'analyst'
  },
  sha256: {
    type: String,
    default: ''
  },
  status: {
    type: String,
    enum: ['processed', 'failed', 'partial'],
    default: 'processed'
  }
}, {
  timestamps: true
});

logFileSchema.index({ createdAt: -1 });

module.exports = mongoose.model('LogFile', logFileSchema);
