const express = require('express');
const router = express.Router();
const rateLimit = require('express-rate-limit');
const { z } = require('zod');
const authController = require('../controllers/authController');
const { authenticate, authorize } = require('../middleware/auth');
const validate = require('../middleware/validate');

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 50,
  message: { error: 'TooManyRequests', message: 'Too many authentication attempts. Please try again later.' }
});

const registerSchema = {
  body: z.object({
    username: z.string().min(3).max(30).regex(/^[a-zA-Z0-9_.-]+$/, 'Username can only contain alphanumeric characters, dots, underscores, and dashes'),
    password: z.string().min(8, 'Password must be at least 8 characters long'),
    fullName: z.string().min(2).max(100),
    email: z.string().email()
  })
};

const loginSchema = {
  body: z.object({
    username: z.string().min(1),
    password: z.string().min(1)
  })
};

const updateRoleSchema = {
  body: z.object({
    role: z.enum(['admin', 'analyst', 'viewer'])
  })
};

router.post('/register', authLimiter, validate(registerSchema), authController.register);
router.post('/login', authLimiter, validate(loginSchema), authController.login);
router.get('/me', authenticate, authController.getMe);
router.patch('/users/:id/role', authenticate, authorize('admin'), validate(updateRoleSchema), authController.updateUserRole);

module.exports = router;
