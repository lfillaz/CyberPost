/**
 * Build Script for Firefox
 */

import fs from 'fs';
import path from 'path';
import { execSync } from 'child_process';
import { fileURLToPath } from 'url';

// ES Module equivalent for __dirname
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Build directory
const FIREFOX_DIR = 'firefox_dist';

// Build for Firefox
console.log('🔧 Building CyberPost for Firefox...');
execSync('npx vite build --outDir firefox_dist', { stdio: 'inherit' });
console.log('✅ Firefox build complete');

// Copy and adjust manifest
console.log('Adjusting manifest for Firefox...');
const manifest = JSON.parse(fs.readFileSync('./manifest.json', 'utf8'));

// Firefox-specific adjustments
manifest.browser_specific_settings = {
  "gecko": {
    "id": "cyberpost@ghostbyte.app"
  }
};

// Remove MV3 specific properties if they exist
if (manifest.action) {
  manifest.browser_action = manifest.action;
  delete manifest.action;
}

fs.writeFileSync(path.join(FIREFOX_DIR, 'manifest.json'), JSON.stringify(manifest, null, 2), 'utf8');
console.log('✅ Firefox manifest created');

console.log('🎉 Firefox build process completed successfully');
