// Load and robustness measurements against a running platform, through the public HTTP API.
//   MAILSHARK_URL=http://127.0.0.1:7380 MS_USER=analyst MS_PASSWORD=… node scripts/platform-load.mjs [--out lab/out/platform-load.json]
// Scenarios: one 100-file batch; four concurrent 25-file batches; an oversized file next to valid
// ones; a suite of malformed and hostile inputs. Uses datasets/phishing_pot (see VALIDATION.md).
import { createHash } from 'node:crypto';
import { mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { zipSync } from 'fflate';

const base = process.env.MAILSHARK_URL ?? 'http://127.0.0.1:7380';
const user = process.env.MS_USER;
const password = process.env.MS_PASSWORD;
if (!user || !password) throw new Error('Set MS_USER and MS_PASSWORD (an investigator or admin account).');
const outPath = process.argv.includes('--out') ? process.argv[process.argv.indexOf('--out') + 1] : 'lab/out/platform-load.json';
const root = process.cwd();

let cookie = '';
let csrf = '';
async function call(method, path, body, form = false) {
  const headers = { accept: 'application/json', ...(cookie ? { cookie } : {}), ...(method !== 'GET' && csrf ? { 'x-csrf-token': csrf } : {}) };
  if (body && !form) headers['content-type'] = 'application/json';
  const res = await fetch(base + path, { method, headers, body: body ? (form ? body : JSON.stringify(body)) : undefined });
  const sc = res.headers.get('set-cookie');
  if (sc && sc.startsWith('ms_session=')) cookie = sc.split(';')[0];
  const data = await res.json().catch(() => null);
  return { status: res.status, data };
}
const ok = (r, what) => {
  if (r.status >= 300) throw new Error(`${what}: HTTP ${r.status} ${JSON.stringify(r.data)}`);
  return r.data;
};

const login = ok(await call('POST', '/api/auth/login', { username: user, password }), 'login');
csrf = login.csrf;

const potDir = join(root, 'datasets', 'phishing_pot', 'email');
const pot = readdirSync(potDir)
  .filter((f) => f.endsWith('.eml'))
  .sort((a, b) => (createHash('sha256').update(a).digest('hex') < createHash('sha256').update(b).digest('hex') ? -1 : 1));
const readSafe = (p) => {
  try {
    return readFileSync(p);
  } catch {
    return null;
  }
};
function potFiles(offset, n) {
  const out = [];
  for (let i = offset; out.length < n && i < pot.length; i++) {
    const b = readSafe(join(potDir, pot[i]));
    if (b) out.push({ name: pot[i], bytes: b });
  }
  return out;
}

async function newCase(name) {
  return ok(await call('POST', '/api/cases', { name, description: 'Created by scripts/platform-load.mjs' }), 'create case').id;
}
async function upload(caseId, files) {
  const fd = new FormData();
  for (const f of files) fd.append('files', new Blob([f.bytes]), f.name);
  const t0 = performance.now();
  const r = await call('POST', `/api/cases/${caseId}/batches`, fd, true);
  return { ...r, ms: Math.round(performance.now() - t0) };
}
async function waitDone(caseId, timeoutMs = 30 * 60_000) {
  const t0 = performance.now();
  for (;;) {
    const p = ok(await call('GET', `/api/cases/${caseId}/progress`), 'progress');
    if (p.done && !p.correlation.pending && p.correlation.correlatedAt) return { ms: Math.round(performance.now() - t0), progress: p };
    if (performance.now() - t0 > timeoutMs) return { ms: Math.round(performance.now() - t0), progress: p, timedOut: true };
    await new Promise((r) => setTimeout(r, 500));
  }
}
const health = async () => ok(await call('GET', '/api/health'), 'health');

const results = { server: base, startedAt: new Date().toISOString(), health: await health(), scenarios: {} };

// 1. One full batch of 100 files.
{
  const caseId = await newCase('Load: 100-file batch');
  const files = potFiles(0, 100);
  const up = await upload(caseId, files);
  const done = await waitDone(caseId);
  const m = done.progress.messages;
  results.scenarios.batch100 = {
    files: files.length,
    bytes: files.reduce((s, f) => s + f.bytes.length, 0),
    uploadStatus: up.status,
    uploadMs: up.ms,
    accepted: up.data?.accepted,
    processingMs: done.ms,
    messages: m,
    messagesPerSecond: Math.round((m.total / ((up.ms + done.ms) / 1000)) * 10) / 10,
    timedOut: !!done.timedOut,
  };
  console.log('batch100', results.scenarios.batch100);
}

// 2. Four concurrent batches of 25 files in four cases.
{
  const ids = await Promise.all([0, 1, 2, 3].map((i) => newCase(`Load: concurrent ${i + 1}`)));
  const t0 = performance.now();
  const ups = await Promise.all(ids.map((id, i) => upload(id, potFiles(100 + i * 25, 25))));
  const dones = await Promise.all(ids.map((id) => waitDone(id)));
  const total = dones.reduce((s, d) => s + d.progress.messages.total, 0);
  results.scenarios.concurrent4x25 = {
    uploadStatuses: ups.map((u) => u.status),
    uploadMs: ups.map((u) => u.ms),
    wallMs: Math.round(performance.now() - t0),
    messages: total,
    analyzed: dones.reduce((s, d) => s + d.progress.messages.analyzed, 0),
    failed: dones.reduce((s, d) => s + d.progress.messages.failed, 0),
    messagesPerSecond: Math.round((total / ((performance.now() - t0) / 1000)) * 10) / 10,
  };
  console.log('concurrent4x25', results.scenarios.concurrent4x25);
}

// 3. Oversized file next to valid ones.
{
  const caseId = await newCase('Load: oversized input');
  const session = ok(await call('GET', '/api/auth/session'), 'session');
  const limitMb = Math.round(session.platform.limits.fileBytes / 1048576);
  const big = Buffer.alloc((limitMb + 10) * 1024 * 1024, 0x41);
  big.write('From: big@example.com\r\nSubject: oversized\r\n\r\n', 0, 'latin1');
  const up = await upload(caseId, [{ name: 'oversized.eml', bytes: big }, ...potFiles(300, 2)]);
  const done = await waitDone(caseId);
  results.scenarios.oversized = {
    bytes: big.length,
    uploadStatus: up.status,
    uploadMs: up.ms,
    outcomes: up.data?.evidence?.map((e) => ({ name: e.originalName, status: e.status, error: e.error?.code ?? null })),
    processingMs: done.ms,
    messages: done.progress.messages,
  };
  console.log('oversized', results.scenarios.oversized);
}

// 4. Malformed and hostile inputs.
{
  const caseId = await newCase('Load: malformed inputs');
  const fixture = readFileSync(join(root, 'fixtures', 'eml', 'paypal-lookalike-credential.eml'));
  const nest = (depth) => {
    let body = 'Content-Type: text/plain\r\n\r\ninnermost\r\n';
    for (let i = 0; i < depth; i++) body = `Content-Type: multipart/mixed; boundary="b${i}"\r\n\r\n--b${i}\r\n${body}--b${i}--\r\n`;
    return Buffer.from(`From: nest@example.com\r\nTo: v@example.com\r\nSubject: deep nesting\r\nMIME-Version: 1.0\r\n${body}`, 'latin1');
  };
  const zipBomb = Buffer.from(zipSync({ 'payload.bin': new Uint8Array(200 * 1024 * 1024) }, { level: 9 }));
  const withAttachment = (name, type, bytes) =>
    Buffer.from(
      `From: a@example.com\r\nTo: v@example.com\r\nSubject: attachment ${name}\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary="x"\r\n\r\n--x\r\nContent-Type: text/plain\r\n\r\nsee attached\r\n--x\r\nContent-Type: ${type}; name="${name}"\r\nContent-Disposition: attachment; filename="${name}"\r\nContent-Transfer-Encoding: base64\r\n\r\n${bytes.toString('base64').replace(/.{76}/g, '$&\r\n')}\r\n--x--\r\n`,
      'latin1',
    );
  const cases = [
    { name: 'truncated.eml', bytes: fixture.subarray(0, Math.floor(fixture.length / 2)) },
    { name: 'deep-nesting-300.eml', bytes: nest(300) },
    { name: 'header-line-2mb.eml', bytes: Buffer.from(`From: h@example.com\r\nSubject: ${'A'.repeat(2 * 1024 * 1024)}\r\n\r\nbody\r\n`, 'latin1') },
    { name: 'twenty-thousand-headers.eml', bytes: Buffer.from(`From: h@example.com\r\nSubject: many headers\r\n${Array.from({ length: 20000 }, (_, i) => `X-H${i}: v`).join('\r\n')}\r\n\r\nbody\r\n`, 'latin1') },
    { name: 'invalid-base64.eml', bytes: Buffer.from('From: b@example.com\r\nSubject: bad base64\r\nMIME-Version: 1.0\r\nContent-Type: text/html\r\nContent-Transfer-Encoding: base64\r\n\r\n!!!!not*base64%%%%\r\n', 'latin1') },
    { name: 'zip-bomb-200mb.eml', bytes: withAttachment('invoice.zip', 'application/zip', zipBomb) },
    { name: 'nul-bytes.eml', bytes: Buffer.concat([Buffer.from('From: n@example.com\r\nSubject: nul\r\n\r\n', 'latin1'), Buffer.alloc(100000, 0)]) },
    { name: 'utf16.eml', bytes: Buffer.from('﻿From: u@example.com\r\nSubject: utf16\r\n\r\nhi', 'utf16le') },
    { name: 'mbox-garbage.mbox', bytes: Buffer.from('From someone Mon Jan  1 00:00:00 2024\n\x00\x01\x02garbage\x00\n', 'latin1') },
    { name: 'fake-ole.msg', bytes: Buffer.concat([Buffer.from([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]), Buffer.alloc(4096, 7)]) },
    { name: 'html-script-bomb.eml', bytes: Buffer.from(`From: s@example.com\r\nSubject: scripts\r\nContent-Type: text/html\r\n\r\n${'<script>while(1){}</script><iframe src="https://example.invalid"></iframe>'.repeat(20000)}`, 'latin1') },
    { name: 'link-flood.eml', bytes: Buffer.from(`From: l@example.com\r\nSubject: links\r\nContent-Type: text/html\r\n\r\n${Array.from({ length: 30000 }, (_, i) => `<a href="https://l${i}.example/p?id=${i}">x</a>`).join('')}`, 'latin1') },
  ];
  const up = await upload(caseId, cases);
  const done = await waitDone(caseId);
  const msgs = ok(await call('GET', `/api/cases/${caseId}/messages?pageSize=500`), 'messages');
  const ev = ok(await call('GET', `/api/cases/${caseId}/evidence`), 'evidence');
  const after = await health();
  results.scenarios.malformed = {
    uploadStatus: up.status,
    uploadMs: up.ms,
    processingMs: done.ms,
    timedOut: !!done.timedOut,
    perFile: ev.map((e) => {
      const m = msgs.items.filter((x) => x.evidenceId === e.id);
      return { name: e.originalName, evidence: e.status, error: e.errorCode, messages: m.map((x) => ({ status: x.status, class: x.class, error: x.error?.code ?? null })) };
    }),
    allTerminal: msgs.items.every((m) => ['analyzed', 'failed', 'duplicate'].includes(m.status)),
    serverHealthyAfter: after.status === 'ok',
  };
  console.log('malformed', JSON.stringify(results.scenarios.malformed, null, 1));
}

results.finishedAt = new Date().toISOString();
results.healthAfter = await health();
mkdirSync(dirname(outPath), { recursive: true });
writeFileSync(outPath, JSON.stringify(results, null, 2));
console.log(`→ ${outPath}`);
