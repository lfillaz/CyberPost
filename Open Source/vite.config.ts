import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { resolve } from 'path';
import { fileURLToPath } from 'url';
import { copyFileSync, mkdirSync, existsSync, readFileSync, writeFileSync } from 'fs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = resolve(__filename, '..');

const logMessage = (msg) => console.log(`\x1b[36m${msg}\x1b[0m`);

function buildIndexHtml(html, jsBundle, cssBundle) {
  let updated = html;
  
  if (jsBundle) {
    const scriptRegex = /<script[^>]*>[\s\S]*?<\/script>/i;
    if (scriptRegex.test(updated)) {
      updated = updated.replace(
        scriptRegex,
        `<script type="module" src="./${jsBundle}"></script>`
      );
      logMessage(`✓ Updated script tag to use ${jsBundle}`);
    } else {
      updated = updated.replace(
        '</body>',
        `  <script type="module" src="./${jsBundle}"></script>\n</body>`
      );
      logMessage(`✓ Added script tag for ${jsBundle}`);
    }
  }

  // Add CSS link before closing head tag if cssBundle exists
  if (cssBundle) {
    // Check if there's already a CSS link with our bundle
    if (!updated.includes(`href="./${cssBundle}"`)) {
      updated = updated.replace(
        '</head>',
        `  <link rel="stylesheet" href="./${cssBundle}" />\n</head>`
      );
      logMessage(`✓ Added CSS link for ${cssBundle}`);
    }
  }

  // Ensure body has the right class for styling
  if (!updated.includes('class="bg-cyber-dark"')) {
    updated = updated.replace('<body', '<body class="bg-cyber-dark"');
    logMessage('✓ Added bg-cyber-dark class to body');
  }

  return updated;
}

// Plugin to handle Chrome extension files
const chromeExtensionPlugin = () => {
  return {
    name: 'chrome-extension-plugin',
    writeBundle(options, bundle) {
      // Copy manifest.json
      const manifestSrc = resolve(__dirname, 'src/manifest.json');
      const manifestDest = resolve(__dirname, 'dist/manifest.json');
      copyFileSync(manifestSrc, manifestDest);
      logMessage('Copied manifest.json');

      // Create icons directory if it doesn't exist
      const distIconsDir = resolve(__dirname, 'dist/icons');
      if (!existsSync(distIconsDir)) {
        mkdirSync(distIconsDir, { recursive: true });
      }

      // Copy icons from public/icons
      const iconSizes = [16, 48, 128];
      const publicIconsDir = resolve(__dirname, 'public/icons'); 
      
      try {
        iconSizes.forEach(size => {
          const iconSrc = resolve(publicIconsDir, `icon-${size}.png`);
          const iconDest = resolve(distIconsDir, `icon-${size}.png`);
          if (existsSync(iconSrc)) {
            copyFileSync(iconSrc, iconDest);
            logMessage(`Copied icon-${size}.png`);
          } else {
            console.warn(`Warning: icon-${size}.png not found in public/icons`);
          }
        });
      } catch (err) {
        console.error('Error copying icons:', err);
      }
      
      // Find the main JS and CSS bundle filenames
      let mainJsFile = '';
      let mainCssFile = '';
      
      for (const fileName in bundle) {
        if (fileName.startsWith('assets/main-') || fileName.startsWith('assets/index-')) {
          if (fileName.endsWith('.js')) {
            mainJsFile = fileName;
          } else if (fileName.endsWith('.css')) {
            mainCssFile = fileName;
          }
        }
      }
      
      if (!mainJsFile) {
        console.warn('Warning: Could not find main JS bundle in build output');
      }
      
      if (!mainCssFile) {
        console.warn('Warning: Could not find CSS bundle in build output');
      }
      
      // Debug info
      logMessage(`Found JS bundle: ${mainJsFile || 'NONE!'}`);
      logMessage(`Found CSS bundle: ${mainCssFile || 'NONE!'}`);
      
      // Check if the index.html is in the dist directory
      let indexPath = resolve(__dirname, 'dist/index.html');
      let srcIndexPath = resolve(__dirname, 'public/index.html');
      
      // If index.html is not in the root, it might be in public subfolder (due to Vite build)
      if (!existsSync(indexPath)) {
        const publicIndexPath = resolve(__dirname, 'dist/public/index.html');
        if (existsSync(publicIndexPath)) {
          // Move the index.html from public subfolder to dist root
          copyFileSync(publicIndexPath, indexPath);
          logMessage('Moved index.html from public subfolder to dist root');
        } else {
          // If neither exists, copy from source
          if (existsSync(srcIndexPath)) {
            copyFileSync(srcIndexPath, indexPath);
            logMessage('Copied index.html from source');
          } else {
            console.warn('Warning: Could not find index.html in any location');
            return;
          }
        }
      }
      
      // Now update the index.html contents
      if (existsSync(indexPath)) {
        let indexContent = readFileSync(indexPath, 'utf-8');
        
        // Create a proper HTML structure with all necessary assets linked
        indexContent = indexContent.replace(
          /<head>[\s\S]*?<\/head>/,
          `<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>CyberPost Lab</title>
    <meta name="description" content="A fully offline, browser-based HTTP request testing tool for cybersecurity researchers" />
    <link rel="icon" href="./icons/icon-16.png" sizes="16x16" />
    <link rel="icon" href="./icons/icon-48.png" sizes="48x48" />
    <link rel="icon" href="./icons/icon-128.png" sizes="128x128" />
    <!-- Add Google Fonts -->
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
  </head>`
        );

        indexContent = buildIndexHtml(indexContent, mainJsFile, mainCssFile);

        writeFileSync(indexPath, indexContent);
        logMessage('Fixed asset references and structure in index.html');
      }
    }
  };
};

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [
    react(),
    chromeExtensionPlugin()
  ],
  resolve: {
    alias: {
      '@': resolve(__dirname, './src'),
    },
  },
  base: './', // Use relative paths instead of absolute paths
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    sourcemap: false, // Disable sourcemaps for production
    minify: true,    // Enable minification
    rollupOptions: {
      input: {
        main: resolve(__dirname, 'public/index.html'),
        serviceWorker: resolve(__dirname, 'src/background/serviceWorker.ts'),
      },
      output: {
        entryFileNames: (chunkInfo) => {
          return chunkInfo.name === 'serviceWorker' 
            ? 'background/serviceWorker.js' 
            : 'assets/[name]-[hash].js';
        },
        assetFileNames: (assetInfo) => {
          // Keep CSS files in assets folder with hash for cache busting
          return 'assets/[name]-[hash][extname]';
        },
        // Ensure proper chunking strategy for Chrome extension
        manualChunks: undefined,
      },
    },
  },
});
