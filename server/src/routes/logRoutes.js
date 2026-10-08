const express = require('express');
const router = express.Router();
const multer = require('multer');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');
const logController = require('../controllers/logController');
const { authenticate, authorize } = require('../middleware/auth');

const uploadDir = path.join(__dirname, '../../uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    const hash = crypto.randomBytes(8).toString('hex');
    const safeName = file.originalname.replace(/[^a-zA-Z0-9.-]/g, '_');
    cb(null, `${Date.now()}-${hash}-${safeName}`);
  }
});

const fileFilter = (req, file, cb) => {
  const allowedExts = ['.csv', '.json', '.txt', '.log'];
  const ext = path.extname(file.originalname).toLowerCase();
  if (allowedExts.includes(ext) || file.mimetype.includes('text') || file.mimetype.includes('json') || file.mimetype.includes('csv')) {
    cb(null, true);
  } else {
    cb(new Error('Only .csv, .json, .txt, and .log files are supported!'), false);
  }
};

const upload = multer({
  storage,
  fileFilter,
  limits: { fileSize: 25 * 1024 * 1024 } // 25MB limit
});

router.post('/upload', authenticate, authorize('admin', 'analyst'), upload.single('file'), logController.uploadLog);
router.post('/parse-preview', authenticate, logController.parsePreview);
router.get('/files', authenticate, logController.getUploadedFiles);
router.get('/files/:id', authenticate, logController.getUploadedFileById);
router.get('/files/:id/raw', authenticate, logController.getRawFileContent);
router.get('/files/:id/download', authenticate, logController.downloadUploadedFile);
router.delete('/files/:id', authenticate, authorize('admin', 'analyst'), logController.deleteUploadedFile);
router.delete('/by-name/:fileName', authenticate, authorize('admin', 'analyst'), logController.deleteUploadedFileByName);
router.post('/reset-all', authenticate, authorize('admin'), logController.resetAllData);

module.exports = router;

