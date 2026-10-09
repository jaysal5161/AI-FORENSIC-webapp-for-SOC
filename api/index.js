const { connectDB } = require('../server/src/config/database');
const app = require('../server/src/server');

module.exports = async (req, res) => {
  try {
    await connectDB();
  } catch (err) {
    console.error('[Vercel Serverless] Database initialization error:', err);
    return res.status(500).json({
      error: 'DatabaseInitializationError',
      message: 'Failed to initialize database engine.'
    });
  }

  // Normalize path if /api was trimmed by routing
  if (req.url && !req.url.startsWith('/api')) {
    req.url = `/api${req.url.startsWith('/') ? '' : '/'}${req.url}`;
  }

  return app(req, res);
};
