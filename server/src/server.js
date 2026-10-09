const path = require('path');
const dotenv = require('dotenv');
// Support execution from either server directory or root directory (Vercel)
dotenv.config({ path: path.join(__dirname, '../.env') });
dotenv.config();

const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const mongoSanitize = require('express-mongo-sanitize');
const fs = require('fs');

const { connectDB } = require('./config/database');
const logger = require('./utils/logger');
const errorHandler = require('./middleware/errorHandler');
const { ensureUploadsDir } = require('./utils/storage');

// Route imports
const authRoutes = require('./routes/authRoutes');
const logRoutes = require('./routes/logRoutes');
const eventRoutes = require('./routes/eventRoutes');
const ruleRoutes = require('./routes/ruleRoutes');
const alertRoutes = require('./routes/alertRoutes');
const caseRoutes = require('./routes/caseRoutes');
const iocRoutes = require('./routes/iocRoutes');
const endpointRoutes = require('./routes/endpointRoutes');
const accountRoutes = require('./routes/accountRoutes');
const timelineRoutes = require('./routes/timelineRoutes');
const attackChainRoutes = require('./routes/attackChainRoutes');
const impactRoutes = require('./routes/impactRoutes');
const reviewRoutes = require('./routes/reviewRoutes');
const reportRoutes = require('./routes/reportRoutes');
const dashboardRoutes = require('./routes/dashboardRoutes');

const app = express();
const PORT = process.env.PORT || 5000;

// Security Middleware (OWASP A05 / API8)
app.use(helmet({
  crossOriginResourcePolicy: { policy: 'same-origin' }
}));

const allowedOrigins = [
  process.env.CLIENT_ORIGIN || 'http://localhost:5173',
  'http://127.0.0.1:5173',
  'http://localhost:3000',
  'http://127.0.0.1:3000'
];

app.use(cors({
  origin: (origin, callback) => {
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin)) return callback(null, true);
    try {
      const url = new URL(origin);
      if (url.hostname === 'vercel.app' || url.hostname.endsWith('.vercel.app')) {
        return callback(null, true);
      }
    } catch (e) {}
    const err = new Error(`CORS policy violation: Origin '${origin}' is not authorized.`);
    err.statusCode = 403;
    callback(err);
  },
  credentials: true
}));

// Body parsers with limits
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// NoSQL Injection Sanitization (OWASP A03 / API1)
app.use(mongoSanitize({
  replaceWith: '_'
}));

// Global rate limiter (OWASP API4)
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 2000,
  standardHeaders: true,
  legacyHeaders: false
});
app.use('/api', globalLimiter);

// Ensure uploads directory exists for storage
ensureUploadsDir();

// Ensure database connection is active (vital for serverless cold-starts)
app.use(async (req, res, next) => {
  try {
    await connectDB();
    next();
  } catch (err) {
    logger.error(`Database connection check failed: ${err.message}`);
    return res.status(500).json({
      error: 'DatabaseError',
      message: 'Database connection is currently unavailable'
    });
  }
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({
    status: 'operational',
    service: 'AEGIS SOC Forensic Platform API',
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
});

// API Routes
app.use('/api/auth', authRoutes);
app.use('/api/logs', logRoutes);
app.use('/api/events', eventRoutes);
app.use('/api/rules', ruleRoutes);
app.use('/api/alerts', alertRoutes);
app.use('/api/cases', caseRoutes);
app.use('/api/iocs', iocRoutes);
app.use('/api/endpoints', endpointRoutes);
app.use('/api/accounts', accountRoutes);
app.use('/api/timeline', timelineRoutes);
app.use('/api/attack-chain', attackChainRoutes);
app.use('/api/impact', impactRoutes);
app.use('/api/review', reviewRoutes);
app.use('/api/reports', reportRoutes);
app.use('/api/dashboard', dashboardRoutes);

// Serve frontend SPA static assets if built
const candidateDistDirs = [
  path.join(__dirname, '../dist'),
  path.join(__dirname, '../client/dist'),
  path.join(__dirname, '../../client/dist')
];

for (const dir of candidateDistDirs) {
  if (fs.existsSync(path.join(dir, 'index.html'))) {
    app.use(express.static(dir));
    app.get('*', (req, res, next) => {
      if (req.url && req.url.startsWith('/api')) return next();
      if (req.url && (req.url.startsWith('/assets/') || req.url.includes('.'))) return next();
      res.sendFile(path.join(dir, 'index.html'));
    });
    break;
  }
}

// Error Handling Middleware
app.use(errorHandler);

// Boot server
async function startServer() {
  try {
    await connectDB();
    const server = app.listen(PORT, () => {
      logger.info(`AEGIS SOC Platform API running on port ${PORT} [${process.env.NODE_ENV || 'development'}]`);
    });
    return server;
  } catch (err) {
    logger.error(`Failed to start server: ${err.message}`);
    process.exit(1);
  }
}

if (require.main === module) {
  startServer();
}

module.exports = app;
