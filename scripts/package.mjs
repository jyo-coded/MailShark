// Release packaging for addons.mozilla.org:  npm run package  [-- --allow-dirty]
//
//   artifacts/mailshark-<version>.zip          the add-on (upload this to AMO)
//   artifacts/mailshark-<version>-source.zip   source for AMO reviewers; `npm ci && npm run build`
//                                              inside it reproduces dist/firefox file for file
//
// The packaged zip is then linted with addons-linter; any error, warning or notice fails the release.
import { spawnSync } from 'node:child_process';
import { mkdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { zipSync } from 'fflate';
import { buildExtension, root } from './build-lib.mjs';

const allowDirty = process.argv.includes('--allow-dirty');
const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
const version = pkg.version;
const out = join(root, 'dist', 'firefox');
const artifacts = join(root, 'artifacts');
const addonZip = join(artifacts, `mailshark-${version}.zip`);
const sourceZip = join(artifacts, `mailshark-${version}-source.zip`);

// Everything a reviewer needs to rebuild the add-on and try it (sample emails), and nothing else.
const SOURCE_PATHS = [
  'package.json',
  'package-lock.json',
  'tsconfig.json',
  'LICENSE',
  'README.md',
  'THIRD_PARTY_NOTICES.md',
  'docs/BUILDING.md',
  'fixtures/eml/',
  'engine/src/',
  'extension/',
  'scripts/build.mjs',
  'scripts/build-lib.mjs',
  'scripts/icons.mjs',
  'scripts/package.mjs',
];

function run(cmd, args, opts = {}) {
  const r = spawnSync(cmd, args, { cwd: root, encoding: 'utf8', ...opts });
  if (r.status !== 0) {
    process.stderr.write(r.stdout ?? '');
    process.stderr.write(r.stderr ?? '');
    throw new Error(`${[cmd, ...args].join(' ')} exited with ${r.status}`);
  }
  return r.stdout ?? '';
}

const git = (...args) => run('git', args);
const inSource = (f) => SOURCE_PATHS.some((p) => (p.endsWith('/') ? f.startsWith(p) : f === p));

// 1. Refuse to package uncommitted source: the source zip must match a commit.
const dirty = git('status', '--porcelain')
  .split('\n')
  .filter(Boolean)
  .map((l) => l.slice(3).replace(/^"|"$/g, ''))
  .filter(inSource);
if (dirty.length && !allowDirty) {
  console.error(`Uncommitted changes in shipped source:\n  ${dirty.join('\n  ')}\nCommit them, or pass --allow-dirty for a local test package.`);
  process.exit(1);
}

// 2. Clean production build.
await buildExtension({ target: 'firefox', out, dev: false });
const manifest = JSON.parse(readFileSync(join(out, 'manifest.json'), 'utf8'));
if (manifest.version !== version) throw new Error(`manifest version ${manifest.version} != package.json ${version}`);
for (const f of ['background.js', 'content.js', 'popup.js', 'lab.js', 'welcome.js']) {
  const code = readFileSync(join(out, f), 'utf8');
  if (/data-mailshark-e2e|sourceMappingURL=data:/.test(code)) throw new Error(`${f} contains test-only or dev-only code`);
  if (/\binnerHTML\s*=[^=]|\beval\(|new Function\(/.test(code)) throw new Error(`${f} contains a forbidden sink`);
}
if (manifest.host_permissions.some((h) => !h.startsWith('https://mail.google.com/'))) throw new Error('Unexpected host permission in release manifest');

// 3. The add-on package.
mkdirSync(artifacts, { recursive: true });
rmSync(addonZip, { force: true });
const webExt = join(root, 'node_modules', 'web-ext', 'bin', 'web-ext.js');
run(process.execPath, [webExt, 'build', '--source-dir', out, '--artifacts-dir', artifacts, '--filename', `mailshark-${version}.zip`, '--overwrite-dest']);

// 4. The source package (tracked files only, fixed timestamps so identical sources give identical zips).
// With --allow-dirty, new (untracked, not ignored) files are included too.
const files = git('ls-files', '-z', ...(allowDirty ? ['--cached', '--others', '--exclude-standard'] : [])).split('\0').filter((f) => f && inSource(f));
for (const required of SOURCE_PATHS.filter((p) => !p.endsWith('/'))) {
  if (!files.includes(required)) throw new Error(`${required} is not committed but belongs in the source package`);
}
const mtime = new Date('2026-01-01T00:00:00Z');
const entries = {};
for (const f of files.sort()) entries[`mailshark-${version}-source/${f}`] = [readFileSync(join(root, f)), { mtime }];
writeFileSync(sourceZip, zipSync(entries, { level: 9 }));

// 5. Lint exactly what will be uploaded.
const linter = join(root, 'node_modules', 'addons-linter', 'bin', 'addons-linter');
const report = JSON.parse(run(process.execPath, [linter, addonZip, '--output', 'json', '--boring']));
const { errors, warnings, notices } = report.summary;
for (const m of [...report.errors, ...report.warnings, ...report.notices]) console.error(`  ${m._type} ${m.code}: ${m.message} (${m.file ?? ''})`);
if (errors || warnings || notices) {
  console.error(`addons-linter: ${errors} errors, ${warnings} warnings, ${notices} notices`);
  process.exit(1);
}

const kib = (p) => `${(statSync(p).size / 1024).toFixed(0)} KiB`;
console.log(`MailShark ${version}
  add-on  ${addonZip} (${kib(addonZip)})
  source  ${sourceZip} (${kib(sourceZip)}, ${files.length} files)
  addons-linter: 0 errors, 0 warnings, 0 notices`);
