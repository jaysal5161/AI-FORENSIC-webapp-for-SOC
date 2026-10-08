const logger = require('../utils/logger');

const errorHandler = (err, req, res, next) => {
  logger.error(`${req.method} ${req.originalUrl} - ${err.message}`, {
    stack: err.stack,
    ip: req.ip
  });

  const statusCode = err.statusCode || err.status || 500;
  const response = {
    error: err.name || 'InternalServerError',
    message: err.message || 'An unexpected error occurred'
  };

  // Prevent leaking internal call stacks or filesystem paths in API responses (OWASP A05 / API8)
  res.status(statusCode).json(response);
};

module.exports = errorHandler;
