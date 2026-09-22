// Shared build logic for the shipping extension (scripts/build.mjs) and the local preview harness
// (scripts/preview.mjs). Bundles are unminified so AMO reviewers can read them.
import { build, context } from 'esbuild';
import { cpSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildManifest } from '../extension/manifest.mjs';

export const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const src = join(root, 'extension', 'src');
const pub = join(root, 'extension', 'public');

// MailShark never uses dangerouslySetInnerHTML; this rewrites Preact's two innerHTML writes (the
// only code path that could set HTML from strings) to plain-text equivalents, so the shipped add-on
// contains no innerHTML assignments at all.
const noInnerHtml = {
  name: 'no-innerhtml',
  setup(b) {
    b.onLoad({ filter: /[\\/]preact[\\/]dist[\\/]preact\.(module\.js|mjs)$/ }, (args) => {
      const before = readFileSync(args.path, 'utf8');
      const code = before
        .replace(/\((\w)\.innerHTML=(\w)\.__html\)/, '($1.textContent=String($2.__html))')
        .replace(/(\w)&&\((\w)\.innerHTML=""\)/, '$1&&($2.textContent="")');
      if (/\.innerHTML\s*=[^=]/.test(code)) throw new Error(`Preact innerHTML patch did not apply to ${args.path}`);
      return { contents: code, loader: 'js' };
    });
  },
};

export const ENTRIES = [
  { in: join(src, 'background', 'index.ts'), out: 'background' },
  { in: join(src, 'content', 'index.tsx'), out: 'content' },
  { in: join(src, 'popup', 'main.tsx'), out: 'popup' },
  { in: join(src, 'lab', 'main.tsx'), out: 'lab' },
  { in: join(src, 'welcome', 'main.tsx'), out: 'welcome' },
];

export function copyStatic(out) {
  cpSync(pub, out, { recursive: true, filter: (p) => !p.endsWith('.gitkeep') });
  if (!existsSync(join(out, 'icons', 'icon-128.png'))) throw new Error('Icons missing: run `npm run icons` first.');
  const fontDir = join(out, 'fonts');
  mkdirSync(fontDir, { recursive: true });
  for (const [pkgName, file, dest] of [
    ['@fontsource-variable/geist', 'geist-latin-wght-normal.woff2', 'geist-latin.woff2'],
    ['@fontsource-variable/geist', 'geist-latin-ext-wght-normal.woff2', 'geist-latin-ext.woff2'],
    ['@fontsource-variable/geist-mono', 'geist-mono-latin-wght-normal.woff2', 'geist-mono-latin.woff2'],
  ]) {
    cpSync(join(root, 'node_modules', pkgName, 'files', file), join(fontDir, dest));
  }
  cpSync(join(root, 'node_modules', '@fontsource-variable', 'geist', 'LICENSE'), join(fontDir, 'LICENSE-Geist.txt'));
  cpSync(join(root, 'node_modules', '@fontsource-variable', 'geist-mono', 'LICENSE'), join(fontDir, 'LICENSE-GeistMono.txt'));
  const css = ['fonts.css', 'tokens.css', 'components.css', 'dissector.css', 'pages.css'].map((f) => readFileSync(join(src, 'ui', 'styles', f), 'utf8')).join('\n');
  writeFileSync(join(out, 'app.css'), css);
}

export async function buildExtension({ target = 'firefox', out, dev = false, watch = false, preview = false, testOrigin = null }) {
  const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
  rmSync(out, { recursive: true, force: true });
  mkdirSync(out, { recursive: true });
  copyStatic(out);
  const manifest = buildManifest({ version: pkg.version, target });
  if (testOrigin) {
    // End-to-end test builds only: also run on the local Gmail mock. Never used for releases.
    // Match patterns cannot carry a port, so the pattern covers the host on any port.
    const u = new URL(testOrigin);
    const pattern = `${u.protocol}//${u.hostname}/*`;
    manifest.host_permissions.push(pattern);
    manifest.content_scripts[0].matches.push(pattern);
    manifest.web_accessible_resources[0].matches.push(pattern);
  }
  writeFileSync(join(out, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n');

  const common = {
    plugins: [noInnerHtml],
    bundle: true,
    format: 'iife',
    platform: 'browser',
    target: target === 'firefox' ? ['firefox140'] : ['chrome120'],
    jsx: 'automatic',
    jsxImportSource: 'preact',
    loader: { '.css': 'text' },
    minify: false,
    // Dead-code elimination only (e.g. test-only branches); identifiers and layout stay readable.
    minifySyntax: !dev,
    sourcemap: dev ? 'inline' : false,
    legalComments: 'eof',
    charset: 'utf8',
    logLevel: 'warning',
    define: {
      'process.env.NODE_ENV': JSON.stringify(dev ? 'development' : 'production'),
      __MS_VERSION__: JSON.stringify(pkg.version),
      __MS_TARGET__: JSON.stringify(target),
      __MS_DEV__: JSON.stringify(dev),
      __MS_PREVIEW__: JSON.stringify(preview || !!testOrigin),
    },
  };
  const options = ENTRIES.map((e) => ({ ...common, entryPoints: { [e.out]: e.in }, outdir: out }));
  if (watch) {
    const ctxs = await Promise.all(options.map((o) => context(o)));
    await Promise.all(ctxs.map((c) => c.watch()));
    return { version: pkg.version, watching: true };
  }
  await Promise.all(options.map((o) => build(o)));
  return { version: pkg.version, watching: false };
}
