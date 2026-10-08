const winston = require('winston');
const path = require('path');
const fs = require('fs');

const isVercel = Boolean(process.env.VERCEL);
const logDir = isVercel
  ? path.join('/tmp', 'logs')
  : path.join(__dirname, '../../logs');

let canWriteFiles = false;
try {
  if (!fs.existsSync(logDir)) {
    fs.mkdirSync(logDir, { recursive: true });
  }
  canWriteFiles = true;
} catch (e) {
  canWriteFiles = false;
}

const transports = [
  new winston.transports.Console({
    format: winston.format.combine(
      winston.format.colorize(),
      winston.format.printf(({ timestamp, level, message, ...meta }) => {
        const metaStr = Object.keys(meta).length && meta.service !== 'soc-platform'
          ? ` ${JSON.stringify(meta)}`
          : '';
        return `[${timestamp}] ${level}: ${message}${metaStr}`;
      })
    )
  })
];

if (canWriteFiles) {
  try {
    transports.push(
      new winston.transports.File({
        filename: path.join(logDir, 'error.log'),
        level: 'error',
        maxsize: 5242880, // 5MB
        maxFiles: 5
      }),
      new winston.transports.File({
        filename: path.join(logDir, 'combined.log'),
        maxsize: 5242880,
        maxFiles: 5
      }),
      new winston.transports.File({
        filename: path.join(logDir, 'audit.log'),
        level: 'info',
        maxsize: 10485760, // 10MB
        maxFiles: 10
      })
    );
  } catch (err) {
    // Graceful fallback to console
  }
}

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    winston.format.errors({ stack: true }),
    winston.format.splat(),
    winston.format.json()
  ),
  defaultMeta: { service: 'soc-platform' },
  transports
});

// Dedicated structured audit log function for security and compliance (OWASP A09)
logger.audit = function (action, meta = {}) {
  logger.info(`[AUDIT] ${action}`, {
    isAudit: true,
    action,
    timestamp: new Date().toISOString(),
    ...meta
  });
};

module.exports = logger;
