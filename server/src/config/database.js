const mongoose = require('mongoose');
const path = require('path');
const fs = require('fs');
const { spawn } = require('child_process');
const logger = require('../utils/logger');

let mongodChild = null;
let memoryServer = null;

function checkPortAvailable(port = 27017) {
  return new Promise((resolve) => {
    const net = require('net');
    const tester = net.createServer()
      .once('error', (err) => {
        if (err.code === 'EADDRINUSE') {
          resolve(false); // Port is in use, meaning MongoDB or another service is listening!
        } else {
          resolve(true);
        }
      })
      .once('listening', () => {
        tester.once('close', () => resolve(true)).close();
      })
      .listen(port, '127.0.0.1');
  });
}

async function connectDB() {
  // If already connected, reuse existing connection (vital for Vercel serverless functions)
  if (mongoose.connection.readyState === 1) {
    return;
  }
  if (mongoose.connection.readyState === 2) {
    await new Promise((resolve) => {
      mongoose.connection.once('connected', resolve);
      setTimeout(resolve, 3000);
    });
    if (mongoose.connection.readyState === 1) return;
  }

  const uri = process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/soc_platform';

  // 1. Try direct connection first
  try {
    await mongoose.connect(uri, {
      serverSelectionTimeoutMS: process.env.VERCEL ? 8000 : 2000
    });
    logger.info(`MongoDB connected directly to: ${uri}`);
    return;
  } catch (err) {
    if (process.env.VERCEL) {
      logger.error(`Vercel MongoDB connection failed to ${uri}: ${err.message}`);
      throw err;
    }
    logger.warn(`Direct MongoDB connection to ${uri} failed: ${err.message}`);
  }

  // 2. Check if local portable mongod.exe exists in server/bin/
  const binDir = path.join(__dirname, '../../bin');
  const possibleMongod = [
    path.join(binDir, 'mongod.exe'),
    path.join(binDir, 'bin/mongod.exe')
  ];

  let foundMongod = null;
  for (const p of possibleMongod) {
    if (fs.existsSync(p)) {
      foundMongod = p;
      break;
    }
  }

  if (foundMongod) {
    logger.info(`Found local portable mongod at: ${foundMongod}`);
    const dbPath = path.join(__dirname, '../../data/db');
    if (!fs.existsSync(dbPath)) {
      fs.mkdirSync(dbPath, { recursive: true });
    }

    const portAvailable = await checkPortAvailable(27017);
    if (portAvailable) {
      logger.info(`Launching local mongod daemon on port 27017 (dbPath: ${dbPath})...`);
      mongodChild = spawn(foundMongod, ['--dbpath', dbPath, '--port', '27017', '--bind_ip', '127.0.0.1'], {
        detached: false,
        stdio: 'ignore'
      });

      // Wait 1.5 seconds for mongod to bind to port
      await new Promise(r => setTimeout(r, 1500));
    }

    try {
      await mongoose.connect(uri, {
        serverSelectionTimeoutMS: 5000
      });
      logger.info(`Connected to local portable MongoDB instance at: ${uri}`);
      return;
    } catch (launchErr) {
      logger.error(`Failed connecting to spawned mongod: ${launchErr.message}`);
    }
  }

  // 3. Fallback to MongoMemoryServer (local dev only)
  try {
    logger.info('Attempting fallback to embedded MongoMemoryServer...');
    let MongoMemoryServer;
    try {
      MongoMemoryServer = require('mongodb-memory-server').MongoMemoryServer;
    } catch (importErr) {
      throw new Error('mongodb-memory-server package is not installed. Please set MONGO_URI.');
    }
    memoryServer = await MongoMemoryServer.create({
      instance: {
        dbName: 'soc_platform'
      }
    });
    const memoryUri = memoryServer.getUri();
    await mongoose.connect(memoryUri);
    logger.info(`Embedded MongoMemoryServer connected successfully at: ${memoryUri}`);
  } catch (memErr) {
    logger.error(`Fatal: Unable to connect to any MongoDB instance: ${memErr.message}`);
    throw memErr;
  }
}

async function disconnectDB() {
  await mongoose.disconnect();
  if (memoryServer) {
    await memoryServer.stop();
  }
  if (mongodChild) {
    try {
      mongodChild.kill();
    } catch (e) {}
  }
}

module.exports = { connectDB, disconnectDB };
