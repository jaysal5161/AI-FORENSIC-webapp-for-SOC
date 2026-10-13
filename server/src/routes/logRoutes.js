const express = require('express');
const router = express.Router();
const multer = require('multer');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');
const logController = require('../controllers/logController');
const { authenticate, authorize } = require('../middleware/auth');
const { uploadsDir, ensureUploadsDir } = require('../utils/storage');

ensureUploadsDir();

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    ensureUploadsDir();
    cb(null, uploadsDir);
  },
  filename: (req, file, cb) => {
    const rawName = file.originalname || 'security_log.txt';
    const ext = path.extname(rawName).toLowerCase() || '.log';
    const baseName = path.basename(rawName, ext);
    // Sanitize filename to prevent path traversal while preserving readable name
    const safeBaseName = baseName.replace(/[^a-zA-Z0-9_-]/g, '_').slice(0, 80);
    const hash = crypto.randomBytes(6).toString('hex');
    cb(null, `${Date.now()}-${hash}-${safeBaseName}${ext}`);
  }
});

const fileFilter = (req, file, cb) => {
  const allowedExts = ['.csv', '.json', '.txt', '.log'];
  const ext = path.extname(file.originalname || '').toLowerCase();
  const mimetype = (file.mimetype || '').toLowerCase();

  if (
    allowedExts.includes(ext) ||
    mimetype.includes('text') ||
    mimetype.includes('json') ||
    mimetype.includes('csv') ||
    mimetype === 'application/octet-stream' ||
    mimetype === 'application/vnd.ms-excel'
  ) {
    cb(null, true);
  } else {
    cb(new Error('Upload failed: Unsupported file format. Supported formats are .csv, .json, .txt, and .log'), false);
  }
};

const upload = multer({
  storage,
  fileFilter,
  limits: {
    fileSize: 25 * 1024 * 1024 // 25MB limit (Phase 2 requirement)
  }
});

// Resilient upload middleware with explicit, friendly error responses
const handleMulterUpload = (req, res, next) => {
  upload.single('file')(req, res, (err) => {
    if (err) {
      if (err instanceof multer.MulterError) {
        if (err.code === 'LIMIT_FILE_SIZE') {
          return res.status(400).json({
            error: 'FileSizeExceeded',
            message: 'Upload failed: File exceeds 25 MB'
          });
        }
        return res.status(400).json({
          error: 'UploadError',
          message: `Upload failed: ${err.message}`
        });
      }
      return res.status(400).json({
        error: 'UnsupportedFormat',
        message: err.message || 'Upload failed: Unsupported file format'
      });
    }
    next();
  });
};

router.post('/upload', authenticate, authorize('admin', 'analyst'), handleMulterUpload, logController.uploadLog);
router.post('/parse-preview', authenticate, logController.parsePreview);
router.get('/files', authenticate, logController.getUploadedFiles);
router.get('/files/:id', authenticate, logController.getUploadedFileById);
router.get('/files/:id/raw', authenticate, logController.getRawFileContent);
router.get('/files/:id/download', authenticate, logController.downloadUploadedFile);
router.delete('/files/:id', authenticate, authorize('admin', 'analyst'), logController.deleteUploadedFile);
router.delete('/by-name/:fileName', authenticate, authorize('admin', 'analyst'), logController.deleteUploadedFileByName);
router.post('/reset-all', authenticate, authorize('admin'), logController.resetAllData);

module.exports = router;
