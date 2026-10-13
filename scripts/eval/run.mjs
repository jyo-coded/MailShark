// Bundles a TypeScript evaluator for Node and runs it with the given arguments.
//   node scripts/eval/run.mjs [evaluate|forensic|correlation|profile] [args…]   (default: evaluate)
import { build } from 'esbuild';
import { spawnSync } from 'node:child_process';
import { mkdirSync } from 'node:fs';
import { join } from 'node:path';

const SCRIPTS = new Set(['evaluate', 'forensic', 'correlation', 'profile', 'benign-analysis']);
const argv = process.argv.slice(2);
const name = SCRIPTS.has(argv[0]) ? argv.shift() : 'evaluate';
const outFile = join(process.cwd(), 'dist', 'eval', `${name}.mjs`);
mkdirSync(join(process.cwd(), 'dist', 'eval'), { recursive: true });
await build({
  entryPoints: [join(process.cwd(), 'scripts', 'eval', `${name}.ts`)],
  bundle: true,
  platform: 'node',
  format: 'esm',
  target: 'node22',
  outfile: outFile,
  logLevel: 'warning',
  banner: { js: "import { createRequire as __r } from 'node:module'; const require = __r(import.meta.url);" },
});
const r = spawnSync(process.execPath, ['--max-old-space-size=4096', '--disable-warning=ExperimentalWarning', outFile, ...argv], { stdio: 'inherit' });
process.exit(r.status ?? 1);
