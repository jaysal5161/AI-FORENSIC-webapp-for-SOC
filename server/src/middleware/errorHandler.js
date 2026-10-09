const logger = require('../utils/logger');

const errorHandler = (err, req, res, next) => {
  logger.error(`${req.method} ${req.originalUrl} - ${err.message}`, {
    stack: err.stack,
    ip: req.ip
  });

  const statusCode = err.statusCode || err.status || 500;
  const isProd = process.env.NODE_ENV === 'production';
  const response = {
    error: err.name || 'InternalServerError',
    message: (statusCode === 500 && isProd) ? 'An unexpected internal error occurred' : (err.message || 'An unexpected error occurred')
  };

  // Prevent leaking internal call stacks or filesystem paths in API responses (OWASP A05 / API8)
  res.status(statusCode).json(response);
};

module.exports = errorHandler;
