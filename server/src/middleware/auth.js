const jwt = require('jsonwebtoken');
const User = require('../models/User');
const JWT_SECRET = process.env.JWT_SECRET || 'soc_forensic_platform_super_secret_jwt_key_2026_at_least_32_chars!';
if (!JWT_SECRET || JWT_SECRET.length < 32) {
  throw new Error('FATAL SECURITY ERROR: process.env.JWT_SECRET must be set and contain at least 32 characters.');
}
const authenticate = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({
        error: 'Unauthorized',
        message: 'No authorization token provided'
      });
    }

    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, JWT_SECRET);

    const user = await User.findById(decoded.id).select('-passwordHash');
    if (!user) {
      return res.status(401).json({
        error: 'Unauthorized',
        message: 'User belonging to token no longer exists'
      });
    }

    req.user = user;
    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Unauthorized', message: 'Token expired' });
    }
    return res.status(401).json({ error: 'Unauthorized', message: 'Invalid token' });
  }
};

const authorize = (...roles) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Unauthorized', message: 'Not authenticated' });
    }
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({
        error: 'Forbidden',
        message: `Role '${req.user.role}' is not authorized to access this resource`
      });
    }
    next();
  };
};

module.exports = { authenticate, authorize, JWT_SECRET };
