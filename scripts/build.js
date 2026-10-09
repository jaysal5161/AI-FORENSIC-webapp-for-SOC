const { execSync } = require('child_process');
const path = require('path');
const fs = require('fs');

console.log('====================================================');
console.log('[AEGIS Build] Starting SOC Platform Unified Build...');
console.log('====================================================');

// A valid repo root must contain client/vite.config.js and server/src/server.js
function isRepoRoot(dir) {
  return fs.existsSync(path.join(dir, 'client', 'vite.config.js')) &&
         fs.existsSync(path.join(dir, 'server', 'src', 'server.js'));
}

let repoRoot = process.cwd();
if (!isRepoRoot(repoRoot)) {
  const p1 = path.resolve(repoRoot, '..');
  const p2 = path.resolve(repoRoot, '../..');
  if (isRepoRoot(p1)) {
    repoRoot = p1;
  } else if (isRepoRoot(p2)) {
    repoRoot = p2;
  }
}

const clientDir = path.join(repoRoot, 'client');
const clientDist = path.join(clientDir, 'dist');
const serverDir = path.join(repoRoot, 'server');
const serverDist = path.join(serverDir, 'dist');
const serverClientDist = path.join(serverDir, 'client', 'dist');

console.log(`[AEGIS Build] Working directory: ${process.cwd()}`);
console.log(`[AEGIS Build] Repository root:    ${repoRoot}`);
console.log(`[AEGIS Build] Client directory:   ${clientDir}`);

if (!fs.existsSync(path.join(clientDir, 'package.json'))) {
  console.error(`[AEGIS Build] ERROR: Cannot locate client package.json at: ${clientDir}`);
  process.exit(1);
}

// 1. Install client dependencies
console.log('\n[AEGIS Build] Step 1: Installing client dependencies...');
try {
  execSync('npm install', { cwd: clientDir, stdio: 'inherit' });
} catch (err) {
  console.error('[AEGIS Build] Failed to install client dependencies:', err.message);
  process.exit(1);
}

// 2. Build client bundle
console.log('\n[AEGIS Build] Step 2: Compiling Vite client bundle...');
try {
  execSync('npm run build', { cwd: clientDir, stdio: 'inherit' });
} catch (err) {
  console.error('[AEGIS Build] Failed to build client application:', err.message);
  process.exit(1);
}

// Helper to recursively copy directories
function copyDirSync(src, dest) {
  if (!fs.existsSync(src)) return;
  if (!fs.existsSync(dest)) fs.mkdirSync(dest, { recursive: true });
  const entries = fs.readdirSync(src, { withFileTypes: true });
  for (const entry of entries) {
    const srcPath = path.join(src, entry.name);
    const destPath = path.join(dest, entry.name);
    if (entry.isDirectory()) {
      copyDirSync(srcPath, destPath);
    } else {
      fs.copyFileSync(srcPath, destPath);
    }
  }
}

// 3. Mirror distribution assets
console.log('\n[AEGIS Build] Step 3: Mirroring build artifacts to deployment targets...');
if (fs.existsSync(clientDist)) {
  copyDirSync(clientDist, serverDist);
  copyDirSync(clientDist, serverClientDist);
  console.log(`[AEGIS Build] Successfully synced artifacts:`);
  console.log(`  -> ${clientDist}`);
  console.log(`  -> ${serverDist}`);
  console.log(`  -> ${serverClientDist}`);
} else {
  console.error(`[AEGIS Build] Warning: Client dist directory not found at: ${clientDist}`);
}

console.log('\n====================================================');
console.log('[AEGIS Build] Build completed successfully! Ready for Vercel deployment.');
console.log('====================================================\n');
