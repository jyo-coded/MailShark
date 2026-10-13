// Builds the forensic platform into dist/platform:
//   server.mjs        API + CLI (Fastify kept external; everything else bundled from source)
//   worker.mjs        analysis worker (engine, formats, correlation)
//   intel-worker.mjs  intelligence download worker
//   web/              single-page client (Preact), stylesheet, fonts
//   node scripts/platform-build.mjs [--watch] [--dev]
import { build, context } from 'esbuild';
import { cpSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const out = join(root, 'dist', 'platform');
const args = new Set(process.argv.slice(2));
const dev = args.has('--dev');
const watch = args.has('--watch');

rmSync(out, { recursive: true, force: true });
mkdirSync(join(out, 'web', 'fonts'), { recursive: true });

const nodeCommon = {
  bundle: true,
  platform: 'node',
  format: 'esm',
  target: 'node22',
  sourcemap: dev ? 'inline' : false,
  logLevel: 'warning',
  outExtension: { '.js': '.mjs' },
  // Fastify and its plugins resolve files at runtime; they stay in node_modules.
  external: ['fastify', '@fastify/*'],
  banner: { js: "import { createRequire as __msCreateRequire } from 'node:module'; const require = __msCreateRequire(import.meta.url);" },
};

const server = [
  { ...nodeCommon, entryPoints: { server: join(root, 'platform', 'server', 'main.ts') }, outdir: out },
  { ...nodeCommon, entryPoints: { worker: join(root, 'platform', 'server', 'jobs', 'worker.ts') }, outdir: out },
  { ...nodeCommon, entryPoints: { 'intel-worker': join(root, 'platform', 'server', 'intel', 'worker.ts') }, outdir: out },
];

const web = {
  entryPoints: { app: join(root, 'platform', 'web', 'main.tsx') },
  outdir: join(out, 'web'),
  bundle: true,
  format: 'iife',
  platform: 'browser',
  target: ['firefox115', 'chrome115', 'safari16'],
  jsx: 'automatic',
  jsxImportSource: 'preact',
  minify: !dev,
  sourcemap: dev ? 'inline' : false,
  legalComments: 'linked',
  logLevel: 'warning',
  define: { 'process.env.NODE_ENV': JSON.stringify(dev ? 'development' : 'production') },
};

function copyStatic() {
  const html = readFileSync(join(root, 'platform', 'web', 'index.html'), 'utf8');
  writeFileSync(join(out, 'web', 'index.html'), html);
  const css = ['tokens.css', 'base.css', 'layout.css', 'components.css', 'views.css', 'graph.css'].map((f) => readFileSync(join(root, 'platform', 'web', 'styles', f), 'utf8')).join('\n');
  writeFileSync(join(out, 'web', 'app.css'), css);
  for (const [pkg, file, dest] of [
    ['@fontsource-variable/geist', 'geist-latin-wght-normal.woff2', 'geist-latin.woff2'],
    ['@fontsource-variable/geist', 'geist-latin-ext-wght-normal.woff2', 'geist-latin-ext.woff2'],
    ['@fontsource-variable/geist-mono', 'geist-mono-latin-wght-normal.woff2', 'geist-mono-latin.woff2'],
  ]) {
    cpSync(join(root, 'node_modules', pkg, 'files', file), join(out, 'web', 'fonts', dest));
  }
  cpSync(join(root, 'extension', 'public', 'icons', 'icon-32.png'), join(out, 'web', 'favicon.png'));
}

copyStatic();
const targets = [...server, web];
if (watch) {
  const ctxs = await Promise.all(targets.map((o) => context(o)));
  await Promise.all(ctxs.map((c) => c.watch()));
  console.log(`Watching platform build → ${out}`);
} else {
  await Promise.all(targets.map((o) => build(o)));
  console.log(`Built MailShark Forensic Platform → ${out}`);
}
