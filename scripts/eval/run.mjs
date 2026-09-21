// Bundles the TypeScript evaluator for Node and runs it with the given arguments.
import { build } from 'esbuild';
import { spawnSync } from 'node:child_process';
import { mkdirSync } from 'node:fs';
import { join } from 'node:path';

const outFile = join(process.cwd(), 'dist', 'eval', 'evaluate.mjs');
mkdirSync(join(process.cwd(), 'dist', 'eval'), { recursive: true });
await build({
  entryPoints: [join(process.cwd(), 'scripts', 'eval', 'evaluate.ts')],
  bundle: true,
  platform: 'node',
  format: 'esm',
  target: 'node22',
  outfile: outFile,
  logLevel: 'warning',
});
const r = spawnSync(process.execPath, ['--max-old-space-size=4096', outFile, ...process.argv.slice(2)], { stdio: 'inherit' });
process.exit(r.status ?? 1);
