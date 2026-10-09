const path = require('path');
const fs = require('fs');

const rootBuildScript = path.resolve(__dirname, '../../scripts/build.js');

if (fs.existsSync(rootBuildScript)) {
  require(rootBuildScript);
} else {
  console.error('[Bridge] Could not find scripts/build.js at', rootBuildScript);
  process.exit(1);
}
