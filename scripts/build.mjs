// MailShark build: node scripts/build.mjs [--dev] [--watch] [--target=firefox|chrome]
import { join } from 'node:path';
import { buildExtension, root } from './build-lib.mjs';

const args = new Set(process.argv.slice(2));
const target = [...args].find((a) => a.startsWith('--target='))?.split('=')[1] ?? 'firefox';
const out = join(root, 'dist', target);
const { version, watching } = await buildExtension({ target, out, dev: args.has('--dev'), watch: args.has('--watch') });
console.log(watching ? `Watching ${target} build → ${out}` : `Built MailShark ${version} for ${target} → ${out}`);
