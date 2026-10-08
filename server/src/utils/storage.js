const path = require('path');
const fs = require('fs');

const isVercel = Boolean(process.env.VERCEL);
const uploadsDir = isVercel
  ? path.resolve('/tmp', 'uploads')
  : path.resolve(__dirname, '../../uploads');

function ensureUploadsDir() {
  try {
    if (!fs.existsSync(uploadsDir)) {
      fs.mkdirSync(uploadsDir, { recursive: true });
    }
  } catch (err) {
    // Graceful fallback in read-only environments
  }
  return uploadsDir;
}

// Initial directory check
ensureUploadsDir();

module.exports = {
  uploadsDir,
  ensureUploadsDir,
  isVercel
};
