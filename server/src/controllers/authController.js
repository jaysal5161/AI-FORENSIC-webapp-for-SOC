const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const { JWT_SECRET } = require('../middleware/auth');
const logger = require('../utils/logger');

async function register(req, res, next) {
  try {
    const { username, password, fullName, email } = req.body;
    if (!username || typeof username !== 'string' || !password || typeof password !== 'string') {
      return res.status(400).json({ error: 'BadRequest', message: 'Username and password must be valid strings' });
    }

    const cleanUsername = username.trim().toLowerCase();
    const existingUser = await User.findOne({ username: cleanUsername });
    if (existingUser) {
      return res.status(400).json({ error: 'Conflict', message: 'Username already taken' });
    }

    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(password, salt);

    // Public registration strictly defaults to 'viewer' role to prevent privilege escalation (OWASP A01 / API2)
    const user = await User.create({
      username: cleanUsername,
      passwordHash,
      fullName: fullName || cleanUsername,
      email: (email && typeof email === 'string') ? email.trim().toLowerCase() : `${cleanUsername}@soc.local`,
      role: 'viewer'
    });

    logger.audit('USER_REGISTERED', {
      actorId: user._id,
      username: user.username,
      role: user.role,
      ip: req.ip
    });

    const token = jwt.sign(
      { id: user._id, username: user.username, role: user.role },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.status(201).json({
      message: 'User registered successfully with viewer privileges',
      token,
      user: {
        id: user._id,
        username: user.username,
        fullName: user.fullName,
        email: user.email,
        role: user.role
      }
    });
  } catch (err) {
    next(err);
  }
}

async function login(req, res, next) {
  try {
    const { username, password } = req.body;
    if (!username || typeof username !== 'string' || !password || typeof password !== 'string') {
      return res.status(401).json({ error: 'Unauthorized', message: 'Invalid username or password' });
    }

    const cleanUsername = username.trim().toLowerCase();
    const user = await User.findOne({ username: cleanUsername });
    if (!user) {
      logger.audit('LOGIN_FAILED', { username: cleanUsername, reason: 'User not found', ip: req.ip });
      return res.status(401).json({ error: 'Unauthorized', message: 'Invalid username or password' });
    }

    const isMatch = await bcrypt.compare(password, user.passwordHash);
    if (!isMatch) {
      logger.audit('LOGIN_FAILED', { username, reason: 'Invalid password', ip: req.ip });
      return res.status(401).json({ error: 'Unauthorized', message: 'Invalid username or password' });
    }

    user.lastLogin = new Date();
    await user.save();

    logger.audit('LOGIN_SUCCESS', {
      actorId: user._id,
      username: user.username,
      role: user.role,
      ip: req.ip
    });

    const token = jwt.sign(
      { id: user._id, username: user.username, role: user.role },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user._id,
        username: user.username,
        fullName: user.fullName,
        email: user.email,
        role: user.role
      }
    });
  } catch (err) {
    next(err);
  }
}

async function getMe(req, res) {
  res.json({
    user: {
      id: req.user._id,
      username: req.user.username,
      fullName: req.user.fullName,
      email: req.user.email,
      role: req.user.role,
      lastLogin: req.user.lastLogin,
      createdAt: req.user.createdAt
    }
  });
}

async function updateUserRole(req, res, next) {
  try {
    const { id } = req.params;
    const { role } = req.body;

    const targetUser = await User.findById(id);
    if (!targetUser) {
      return res.status(404).json({ error: 'NotFound', message: 'User not found' });
    }

    const oldRole = targetUser.role;
    targetUser.role = role;
    await targetUser.save();

    logger.audit('USER_ROLE_UPDATED', {
      adminId: req.user._id,
      targetUserId: targetUser._id,
      targetUsername: targetUser.username,
      oldRole,
      newRole: role,
      ip: req.ip
    });

    res.json({
      message: `Role for user ${targetUser.username} updated from ${oldRole} to ${role}`,
      user: {
        id: targetUser._id,
        username: targetUser.username,
        role: targetUser.role
      }
    });
  } catch (err) {
    next(err);
  }
}

module.exports = {
  register,
  login,
  getMe,
  updateUserRole
};

