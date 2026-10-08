const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const Event = require('../models/Event');
const Alert = require('../models/Alert');
const IOC = require('../models/IOC');
const LogFile = require('../models/LogFile');
const parserService = require('../services/parserService');
const normalizationService = require('../services/normalizationService');
const iocExtractionService = require('../services/iocExtractionService');
const threatIntelService = require('../services/threatIntelService');
const profilingService = require('../services/profilingService');
const detectionService = require('../services/detectionService');
const logger = require('../utils/logger');

function detectFormat(fileName, content) {
  const ext = path.extname(fileName).toLowerCase();
  if (ext === '.csv') return 'csv';
  if (ext === '.json') return 'json';
  const trimmed = content.trim();
  if (trimmed.startsWith('{') || trimmed.startsWith('[')) return 'json';
  if (trimmed.includes('sshd') || trimmed.includes('syslog') || /^[A-Z][a-z]{2}\s+\d+/.test(trimmed)) return 'syslog';
  if (ext === '.log') return 'syslog';
  return 'text';
}

async function uploadLog(req, res, next) {
  try {
    const saveFileOption = req.body.saveFile !== 'false' && req.body.saveFile !== false;
    let content = '';
    let fileName = 'raw_log.txt';
    let storedName = '';
    let storedPath = '';
    let fileSize = 0;

    const uploadsDir = path.join(__dirname, '../../uploads');
    if (!fs.existsSync(uploadsDir)) {
      fs.mkdirSync(uploadsDir, { recursive: true });
    }

    if (req.file) {
      fileName = req.file.originalname;
      storedName = req.file.filename;
      storedPath = req.file.path;
      content = fs.readFileSync(storedPath, 'utf8');
      fileSize = req.file.size || Buffer.byteLength(content, 'utf8');

      if (!saveFileOption) {
        // User explicitly chose not to retain the raw file in disk archive
        try {
          fs.unlinkSync(storedPath);
          storedPath = '';
          storedName = '';
        } catch (e) {
          logger.warn(`Could not unlink temporary upload file: ${e.message}`);
        }
      }
    } else if (req.body.content) {
      content = req.body.content;
      fileName = req.body.fileName || 'manual_entry.log';
      fileSize = Buffer.byteLength(content, 'utf8');

      if (saveFileOption) {
        const hash = crypto.randomBytes(8).toString('hex');
        const safeName = fileName.replace(/[^a-zA-Z0-9.-]/g, '_');
        storedName = `${Date.now()}-${hash}-${safeName}`;
        storedPath = path.join(uploadsDir, storedName);
        fs.writeFileSync(storedPath, content, 'utf8');
      }
    } else {
      return res.status(400).json({ error: 'BadRequest', message: 'No file or content uploaded' });
    }

    // 1. Parse raw content
    const rawRecords = parserService.parseFile(fileName, content);
    if (!rawRecords || rawRecords.length === 0) {
      if (storedPath && fs.existsSync(storedPath)) {
        try { fs.unlinkSync(storedPath); } catch (e) {}
      }
      return res.status(400).json({
        error: 'ParseError',
        message: 'No valid records could be parsed from the provided log file'
      });
    }

    // 2. Normalize to Common Event Model
    const normalizedEvents = normalizationService.normalizeRecords(rawRecords, fileName);

    // 3. Insert events in chunks
    const CHUNK_SIZE = 250;
    const insertedEvents = [];
    for (let i = 0; i < normalizedEvents.length; i += CHUNK_SIZE) {
      const chunk = normalizedEvents.slice(i, i + CHUNK_SIZE);
      const inserted = await Event.insertMany(chunk, { ordered: false });
      insertedEvents.push(...inserted);
    }

    // 4. Post-processing pipeline
    // A. IOC extraction
    const iocsExtracted = await iocExtractionService.extractAndStoreIOCs(insertedEvents);

    // B. Threat intel enrichment
    const recentIOCs = await IOC.find().sort({ updatedAt: -1 }).limit(100);
    await threatIntelService.enrichIOCs(recentIOCs);

    // C. Asset & account profiling
    await profilingService.updateProfilesFromEvents(insertedEvents);

    // D. Detection engine
    const alertsGenerated = await detectionService.runDetectionEngine(insertedEvents);

    // 5. Generate SHA256 forensic checksum
    const sha256 = crypto.createHash('sha256').update(content).digest('hex');
    const format = detectFormat(fileName, content);

    // 6. Record LogFile archive in DB
    const logFileRecord = await LogFile.create({
      fileName,
      storedName,
      filePath: storedPath,
      fileSize,
      mimeType: req.file ? req.file.mimetype : 'text/plain',
      format,
      eventsCount: insertedEvents.length,
      iocsCount: iocsExtracted,
      alertsCount: alertsGenerated.length,
      isSaved: Boolean(storedPath),
      uploadedBy: req.user?.username || 'analyst',
      sha256,
      status: 'processed'
    });

    logger.info(`Log ingestion pipeline finished for ${fileName}: ${insertedEvents.length} events, ${iocsExtracted} IOCs, ${alertsGenerated.length} alerts. (Archive Saved: ${Boolean(storedPath)})`);

    res.status(201).json({
      message: 'Logs processed and normalized successfully',
      summary: {
        fileName,
        eventsInserted: insertedEvents.length,
        iocsExtracted,
        alertsGenerated: alertsGenerated.length,
        isSaved: Boolean(storedPath),
        logFileId: logFileRecord._id,
        errors: 0
      },
      logFile: logFileRecord
    });
  } catch (err) {
    logger.error(`Error in log upload pipeline: ${err.message}`);
    next(err);
  }
}

async function getUploadedFiles(req, res, next) {
  try {
    const files = await LogFile.find().sort({ createdAt: -1 });
    res.json(files);
  } catch (err) {
    next(err);
  }
}

async function getUploadedFileById(req, res, next) {
  try {
    const file = await LogFile.findById(req.params.id);
    if (!file) {
      return res.status(404).json({ error: 'NotFound', message: 'Uploaded log file not found' });
    }
    res.json(file);
  } catch (err) {
    next(err);
  }
}

async function getRawFileContent(req, res, next) {
  try {
    const file = await LogFile.findById(req.params.id);
    if (!file) {
      return res.status(404).json({ error: 'NotFound', message: 'Log file record not found' });
    }

    if (!file.isSaved || !file.filePath || !fs.existsSync(file.filePath)) {
      // If physical file on disk is not present (e.g. seeded baseline), generate reconstructed raw CEM sample
      const events = await Event.find({ rawFile: file.fileName }).limit(100);
      if (events.length > 0) {
        const previewText = events.map(e => `[${new Date(e.timestamp).toISOString()}] [${e.source.toUpperCase()}] [${e.severity.toUpperCase()}] ${e.host} \\ ${e.username} - ${e.description} (raw: ${JSON.stringify(e.raw)})`).join('\n');
        return res.json({
          id: file._id,
          fileName: file.fileName,
          sha256: file.sha256,
          format: file.format,
          fileSize: file.fileSize,
          totalLines: events.length,
          isTruncated: false,
          isReconstructed: true,
          content: previewText
        });
      }
      return res.status(404).json({
        error: 'FileNotFound',
        message: 'Raw log file content was not archived on disk for this file.'
      });
    }

    const uploadsDir = path.resolve(__dirname, '../../uploads');
    const resolvedPath = path.resolve(file.filePath);
    if (!resolvedPath.startsWith(uploadsDir)) {
      return res.status(403).json({ error: 'Forbidden', message: 'Access denied: File outside authorized storage directory.' });
    }

    const rawText = fs.readFileSync(resolvedPath, 'utf8');
    const lines = rawText.split('\n');
    const isTruncated = lines.length > 2000;
    const content = isTruncated ? lines.slice(0, 2000).join('\n') : rawText;

    res.json({
      id: file._id,
      fileName: file.fileName,
      sha256: file.sha256,
      format: file.format,
      fileSize: file.fileSize,
      totalLines: lines.length,
      isTruncated,
      content
    });
  } catch (err) {
    next(err);
  }
}

async function downloadUploadedFile(req, res, next) {
  try {
    const file = await LogFile.findById(req.params.id);
    if (!file) {
      return res.status(404).json({ error: 'NotFound', message: 'Log file record not found' });
    }
    const safeDownloadName = (file.fileName || 'log-archive.txt').replace(/[^a-zA-Z0-9._-]/g, '_');
    if (!file.isSaved || !file.filePath || !fs.existsSync(file.filePath)) {
      // If file not on disk, return reconstructed text or error
      const events = await Event.find({ rawFile: file.fileName });
      if (events.length > 0) {
        res.setHeader('Content-Disposition', `attachment; filename="${safeDownloadName}"`);
        res.setHeader('Content-Type', file.mimeType || 'text/plain');
        const content = events.map(e => `${new Date(e.timestamp).toISOString()},${e.source},${e.host},${e.username},${e.sourceIP},${e.destinationIP},${e.eventType},${e.action},${e.status},${e.severity},${e.techniqueId},"${e.description.replace(/"/g, '""')}"`).join('\n');
        return res.send(content);
      }
      return res.status(404).json({ error: 'FileNotFound', message: 'Raw log file is not archived on disk' });
    }

    const uploadsDir = path.resolve(__dirname, '../../uploads');
    const resolvedPath = path.resolve(file.filePath);
    if (!resolvedPath.startsWith(uploadsDir)) {
      return res.status(403).json({ error: 'Forbidden', message: 'Access denied: File outside authorized storage directory.' });
    }

    res.download(resolvedPath, safeDownloadName);
  } catch (err) {
    next(err);
  }
}

async function deleteUploadedFile(req, res, next) {
  try {
    const file = await LogFile.findById(req.params.id);
    if (!file) {
      return res.status(404).json({ error: 'NotFound', message: 'Log file record not found' });
    }

    const fileName = file.fileName;
    const storedName = file.storedName;
    const safeRegex = new RegExp('^' + fileName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '$', 'i');

    let eventsDeleted = 0;
    const purgeEvents = req.query.purgeEvents !== 'false';
    if (purgeEvents) {
      // Find event IDs first so we can remove associated alerts
      const eventsToPurge = await Event.find({
        $or: [
          { rawFile: fileName },
          { rawFile: storedName },
          { rawFile: safeRegex }
        ]
      }).select('_id');
      const eventIds = eventsToPurge.map(e => e._id);

      const delAlerts = await Alert.deleteMany({
        $or: [
          { rawFile: fileName },
          { rawFile: storedName },
          { rawFile: safeRegex },
          { matchingEvents: { $in: eventIds } }
        ]
      });
      logger.info(`Purged ${delAlerts.deletedCount} alerts associated with deleted log file ${fileName}`);

      const delRes = await Event.deleteMany({
        $or: [
          { rawFile: fileName },
          { rawFile: storedName },
          { rawFile: safeRegex }
        ]
      });
      eventsDeleted = delRes.deletedCount;
      logger.info(`Purged ${eventsDeleted} CEM events associated with deleted log file ${fileName}`);
    }

    // Remove physical file from disk if present
    if (file.filePath && fs.existsSync(file.filePath)) {
      try {
        fs.unlinkSync(file.filePath);
        logger.info(`Unlinked stored file ${file.filePath}`);
      } catch (e) {
        logger.warn(`Could not unlink file ${file.filePath}: ${e.message}`);
      }
    }

    // Delete this file and any duplicate LogFile records for the same fileName
    await LogFile.deleteMany({
      $or: [
        { _id: file._id },
        { fileName: fileName },
        { fileName: safeRegex }
      ]
    });

    res.json({
      message: 'Log file and associated events and alerts deleted successfully',
      deletedFile: fileName,
      eventsDeleted
    });
  } catch (err) {
    next(err);
  }
}

async function deleteUploadedFileByName(req, res, next) {
  try {
    const { fileName } = req.params;
    const safeRegex = new RegExp('^' + fileName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '$', 'i');

    const files = await LogFile.find({ $or: [{ fileName }, { fileName: safeRegex }] });
    for (const f of files) {
      if (f.filePath && fs.existsSync(f.filePath)) {
        try { fs.unlinkSync(f.filePath); } catch (e) {}
      }
    }

    const eventsToPurge = await Event.find({
      $or: [
        { rawFile: fileName },
        { rawFile: safeRegex }
      ]
    }).select('_id');
    const eventIds = eventsToPurge.map(e => e._id);

    const delAlerts = await Alert.deleteMany({
      $or: [
        { rawFile: fileName },
        { rawFile: safeRegex },
        { matchingEvents: { $in: eventIds } }
      ]
    });
    logger.info(`Purged ${delAlerts.deletedCount} alerts for ${fileName}`);

    const delEvents = await Event.deleteMany({
      $or: [
        { rawFile: fileName },
        { rawFile: safeRegex }
      ]
    });

    await LogFile.deleteMany({ $or: [{ fileName }, { fileName: safeRegex }] });

    res.json({
      message: `Deleted file ${fileName}, purged ${delEvents.deletedCount} events and ${delAlerts.deletedCount} alerts`,
      fileName,
      eventsDeleted: delEvents.deletedCount,
      alertsDeleted: delAlerts.deletedCount
    });
  } catch (err) {
    next(err);
  }
}

async function resetAllData(req, res, next) {
  try {
    const Case = require('../models/Case');
    const TimelineEntry = require('../models/TimelineEntry');
    const AttackChain = require('../models/AttackChain');
    const ImpactAssessment = require('../models/ImpactAssessment');
    const Evidence = require('../models/Evidence');
    const Endpoint = require('../models/Endpoint');
    const Account = require('../models/Account');

    // 1. Purge all events
    const evRes = await Event.deleteMany({});

    // 2. Purge all log files
    const lfRes = await LogFile.deleteMany({});

    // 3. Purge all alerts
    const alRes = await Alert.deleteMany({});

    // 4. Purge all cases and related investigation artifacts
    const csRes = await Case.deleteMany({});
    await TimelineEntry.deleteMany({});
    await AttackChain.deleteMany({});
    await ImpactAssessment.deleteMany({});
    await Evidence.deleteMany({});
    await IOC.deleteMany({});

    // 5. Reset asset and account risk profiles
    await Endpoint.updateMany({}, {
      $set: { riskScore: 0, status: 'healthy', associatedAlerts: [] }
    });
    await Account.updateMany({}, {
      $set: { riskScore: 0, status: 'active', failedLogins: 0, associatedAlerts: [] }
    });

    // 6. Delete physical uploaded files from disk
    const uploadsDir = path.join(__dirname, '../../uploads');
    if (fs.existsSync(uploadsDir)) {
      const files = fs.readdirSync(uploadsDir);
      for (const f of files) {
        if (f !== '.gitkeep') {
          try {
            fs.unlinkSync(path.join(uploadsDir, f));
          } catch (e) {}
        }
      }
    }

    logger.info(`All log data, alerts, cases and telemetry reset: ${evRes.deletedCount} events, ${lfRes.deletedCount} files, ${alRes.deletedCount} alerts, ${csRes.deletedCount} cases.`);

    res.json({
      message: 'System telemetry and all log files completely reset to 0.',
      summary: {
        eventsDeleted: evRes.deletedCount,
        filesDeleted: lfRes.deletedCount,
        alertsDeleted: alRes.deletedCount,
        casesDeleted: csRes.deletedCount
      }
    });
  } catch (err) {
    logger.error(`Error resetting system telemetry: ${err.message}`);
    next(err);
  }
}

async function parsePreview(req, res, next) {
  try {
    const { content, fileName } = req.body;
    if (!content) {
      return res.status(400).json({ error: 'BadRequest', message: 'Content required for preview' });
    }
    const rawRecords = parserService.parseFile(fileName || 'sample.log', content).slice(0, 5);
    const normalized = normalizationService.normalizeRecords(rawRecords, fileName || 'sample.log');
    res.json({ count: normalized.length, preview: normalized });
  } catch (err) {
    next(err);
  }
}

module.exports = {
  uploadLog,
  getUploadedFiles,
  getUploadedFileById,
  getRawFileContent,
  downloadUploadedFile,
  deleteUploadedFile,
  deleteUploadedFileByName,
  resetAllData,
  parsePreview
};
