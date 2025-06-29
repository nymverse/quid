#!/usr/bin/env node

/**
 * QuID Browser Extension Build Script
 * Creates distribution packages for Chrome and Firefox
 */

const fs = require('fs-extra');
const path = require('path');

const SOURCE_DIR = path.join(__dirname, '..');
const DIST_DIR = path.join(SOURCE_DIR, 'dist');
const CHROME_DIR = path.join(DIST_DIR, 'chrome');
const FIREFOX_DIR = path.join(DIST_DIR, 'firefox');

async function main() {
  const target = process.argv[2] || 'all';
  
  console.log('🔨 Building QuID Browser Extension...');
  
  try {
    // Clean dist directory
    await fs.remove(DIST_DIR);
    await fs.ensureDir(DIST_DIR);
    
    if (target === 'chrome' || target === 'all') {
      await buildChrome();
    }
    
    if (target === 'firefox' || target === 'all') {
      await buildFirefox();
    }
    
    console.log('✅ Build completed successfully!');
    
  } catch (error) {
    console.error('❌ Build failed:', error);
    process.exit(1);
  }
}

async function buildChrome() {
  console.log('📦 Building Chrome extension...');
  
  await fs.ensureDir(CHROME_DIR);
  
  // Copy source files
  await copyCommonFiles(CHROME_DIR);
  
  // Copy Chrome-specific manifest
  await fs.copy(
    path.join(SOURCE_DIR, 'manifest/manifest_v3.json'),
    path.join(CHROME_DIR, 'manifest.json')
  );
  
  console.log('✅ Chrome extension built');
}

async function buildFirefox() {
  console.log('🦊 Building Firefox extension...');
  
  await fs.ensureDir(FIREFOX_DIR);
  
  // Copy source files
  await copyCommonFiles(FIREFOX_DIR);
  
  // Copy Firefox-specific manifest (v2)
  await fs.copy(
    path.join(SOURCE_DIR, 'manifest/manifest_v2.json'),
    path.join(FIREFOX_DIR, 'manifest.json')
  );
  
  // Firefox-specific modifications
  const manifest = await fs.readJson(path.join(FIREFOX_DIR, 'manifest.json'));
  
  // Add Firefox-specific fields
  manifest.browser_specific_settings = {
    gecko: {
      id: 'quid@quid.dev',
      strict_min_version: '90.0'
    }
  };
  
  // Update action to browser_action for v2
  if (manifest.action) {
    manifest.browser_action = manifest.action;
    delete manifest.action;
  }
  
  await fs.writeJson(path.join(FIREFOX_DIR, 'manifest.json'), manifest, { spaces: 2 });
  
  console.log('✅ Firefox extension built');
}

async function copyCommonFiles(targetDir) {
  // Copy source files
  await fs.copy(path.join(SOURCE_DIR, 'src'), path.join(targetDir, 'src'));
  
  // Copy popup
  await fs.copy(path.join(SOURCE_DIR, 'popup'), path.join(targetDir, 'popup'));
  
  // Copy options
  await fs.copy(path.join(SOURCE_DIR, 'options'), path.join(targetDir, 'options'));
  
  // Create icons directory with placeholder icons
  const iconsDir = path.join(targetDir, 'icons');
  await fs.ensureDir(iconsDir);
  
  // Create placeholder icon files
  const iconSizes = [16, 32, 48, 128];
  const iconStates = ['', '-active', '-pending', '-inactive'];
  
  for (const size of iconSizes) {
    for (const state of iconStates) {
      const iconPath = path.join(iconsDir, `icon${state}-${size}.png`);
      await createPlaceholderIcon(iconPath, size);
    }
  }
  
  // Copy main files to root
  await fs.copy(path.join(SOURCE_DIR, 'src/background.js'), path.join(targetDir, 'background.js'));
  await fs.copy(path.join(SOURCE_DIR, 'src/content-script.js'), path.join(targetDir, 'content-script.js'));
  await fs.copy(path.join(SOURCE_DIR, 'src/injected-script.js'), path.join(targetDir, 'injected-script.js'));
  
  // Create README
  await createReadme(targetDir);
}

async function createPlaceholderIcon(iconPath, size) {
  // Create a simple SVG icon and save as PNG placeholder
  const svgContent = `
    <svg width="${size}" height="${size}" xmlns="http://www.w3.org/2000/svg">
      <rect width="${size}" height="${size}" fill="#667eea" rx="4"/>
      <text x="50%" y="50%" text-anchor="middle" dy="0.3em" 
            fill="white" font-family="Arial" font-size="${size * 0.4}" font-weight="bold">Q</text>
    </svg>
  `;
  
  // For a real implementation, you'd convert SVG to PNG
  // For now, we'll just create a placeholder file
  await fs.writeFile(iconPath, `<!-- SVG Placeholder for ${size}x${size} icon -->\n${svgContent}`);
}

async function createReadme(targetDir) {
  const readmeContent = `# QuID Browser Extension

## Installation

### Chrome
1. Open Chrome and navigate to \`chrome://extensions/\`
2. Enable "Developer mode"
3. Click "Load unpacked" and select this directory

### Firefox
1. Open Firefox and navigate to \`about:debugging\`
2. Click "This Firefox"
3. Click "Load Temporary Add-on" and select the manifest.json file

## Features

- ✅ Quantum-resistant authentication
- ✅ WebAuthn enhancement and replacement
- ✅ Universal identity management
- ✅ Cross-platform compatibility
- ✅ Privacy-first design

## Usage

1. Install the extension
2. Install the QuID native host application
3. Create your first QuID identity
4. Start using secure authentication on websites

## Support

For support and documentation, visit: https://quid.dev

## License

MIT License - see LICENSE file for details
`;

  await fs.writeFile(path.join(targetDir, 'README.md'), readmeContent);
}

if (require.main === module) {
  main();
}

module.exports = { buildChrome, buildFirefox, copyCommonFiles };