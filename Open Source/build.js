

import fs from 'fs';
import path from 'path';
import { execSync } from 'child_process';
import { fileURLToPath } from 'url';


const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);


console.log('🔧 Building CyberPost for Chrome...');
execSync('npx vite build', { stdio: 'inherit' });
console.log('✅ Chrome build complete');


fs.copyFileSync('./manifest.json', './dist/manifest.json');
console.log('✅ Manifest copied to dist');

console.log('🎉 Build process completed successfully');
