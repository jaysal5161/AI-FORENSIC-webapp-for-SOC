const { loadDatabase, persistSync } = require('../db/sqlite');
const logger = require('../utils/logger');

let isConnected = false;

async function connectDB() {
  if (isConnected) return;
  try {
    loadDatabase();
    isConnected = true;
    logger.info('Connected to embedded zero-config SOC database successfully (Serverless Ready, Zero Environment Variables Required).');
  } catch (err) {
    logger.error(`Failed connecting to database: ${err.message}`);
    throw err;
  }
}

async function disconnectDB() {
  persistSync();
  isConnected = false;
}

module.exports = { connectDB, disconnectDB };
