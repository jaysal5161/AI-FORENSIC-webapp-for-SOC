const { connectDB } = require('../src/config/database');
const app = require('../src/server');

module.exports = async (req, res) => {
  try {
    await connectDB();
  } catch (err) {
    console.error('[Vercel Serverless] Database connection error:', err);
    return res.status(500).json({
      error: 'DatabaseConnectionError',
      message: 'Failed to connect to database. Please check MONGO_URI in Vercel environment variables.'
    });
  }

  // Normalize path if /api was trimmed by routing
  if (req.url && !req.url.startsWith('/api')) {
    req.url = `/api${req.url.startsWith('/') ? '' : '/'}${req.url}`;
  }

  return app(req, res);
};
