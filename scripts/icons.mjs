// Renders the brand SVGs to the PNG sizes browsers and stores need.
import { Resvg } from '@resvg/resvg-js';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { appIconSvg, smallIconSvg } from '../extension/brand/mark.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const outDir = join(root, 'extension', 'public', 'icons');
mkdirSync(outDir, { recursive: true });

function render(svg, size) {
  return new Resvg(svg, { fitTo: { mode: 'width', value: size }, background: 'rgba(0,0,0,0)' }).render().asPng();
}

for (const size of [16, 32]) writeFileSync(join(outDir, `icon-${size}.png`), render(smallIconSvg(size), size));
for (const size of [48, 96, 128, 256, 512]) writeFileSync(join(outDir, `icon-${size}.png`), render(appIconSvg(size), size));
writeFileSync(join(outDir, 'icon.svg'), appIconSvg(128));
console.log('Icons written to', outDir);
