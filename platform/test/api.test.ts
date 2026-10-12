// End-to-end: upload → expansion → analysis → correlation → reports, through the real HTTP API,
// worker pool and databases. Also access control, limits, failure isolation and recovery.
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { unzipSync, strFromU8 } from 'fflate';
import Ajv2020 from 'ajv/dist/2020.js';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { Client, multipart, startPlatform, waitFor, type TestPlatform } from './helpers';
import { REPORT_JSON_SCHEMA } from '../server/reports/schema';
import { verifyReportHash, type ForensicReport } from '../server/reports/model';

const FX = join(__dirname, '..', '..', 'fixtures', 'eml');
const fixtures = readdirSync(FX).filter((f) => f.endsWith('.eml')).sort();
const read = (f: string): Buffer => readFileSync(join(FX, f));
const PASSWORD = 'correct horse battery staple';

let p: TestPlatform;
let admin: Client;
let caseId = '';
let batchId = '';

beforeAll(async () => {
  p = await startPlatform();
  admin = new Client(p.app);
}, 120_000);

afterAll(async () => {
  await p?.close();
});

describe('setup and authentication', () => {
  it('requires the one-time setup token to create the first administrator', async () => {
    expect((await admin.call('GET', '/api/setup')).json().needed).toBe(true);
    const bad = await admin.call('POST', '/api/setup', { token: 'wrong', username: 'admin', password: PASSWORD, displayName: 'Lead Examiner' });
    expect(bad.status).toBe(403);
    const ok = await admin.call('POST', '/api/setup', { token: p.ctx.setupToken, username: 'admin', password: PASSWORD, displayName: 'Lead Examiner' });
    expect(ok.status).toBe(200);
    expect((await admin.call('POST', '/api/setup', { token: 'anything', username: 'x', password: PASSWORD })).status).toBe(403);
  });

  it('rejects bad credentials, unauthenticated calls and requests without the CSRF token', async () => {
    expect((await admin.call('POST', '/api/auth/login', { username: 'admin', password: 'wrong password!!' })).status).toBe(401);
    expect((await admin.call('GET', '/api/cases')).status).toBe(401);
    await admin.login('admin', PASSWORD);
    expect((await admin.call('GET', '/api/cases')).status).toBe(200);
    const noCsrf = await p.app.inject({ method: 'POST', url: '/api/cases', payload: { name: 'x' }, headers: { cookie: admin.cookie } });
    expect(noCsrf.statusCode).toBe(403);
    expect(JSON.parse(noCsrf.body).error.code).toBe('csrf');
  });

  it('sends hardened security headers', async () => {
    const r = await admin.call('GET', '/api/health');
    expect(String(r.headers['content-security-policy'])).toContain("default-src 'self'");
    expect(String(r.headers['content-security-policy'])).toContain("frame-ancestors 'none'");
    expect(r.headers['x-content-type-options']).toBe('nosniff');
    expect(r.headers['cache-control']).toBe('no-store');
  });
});

describe('evidence intake and analysis', () => {
  it('creates a case and accepts a mixed batch with per-file outcomes', async () => {
    const c = await admin.call('POST', '/api/cases', { name: 'Operation Test Kitchen', reference: 'CASE-2026-001' });
    expect(c.status).toBe(200);
    caseId = c.json().id;
    // An mbox holding two messages, one of which is byte-identical to an uploaded .eml.
    const mbox = Buffer.concat([Buffer.from('From a@b Mon Sep 21 10:00:00 2026\n'), read('legit-newsletter.eml'), Buffer.from('\nFrom a@b Mon Sep 21 10:00:01 2026\n'), Buffer.from('From: Alice <alice@example.org>\nTo: bob@example.org\nSubject: Lunch\nDate: Mon, 21 Sep 2026 10:00:00 +0000\nMessage-ID: <l1@example.org>\n\nShall we meet at noon?\n'), Buffer.from('\n')]);
    const files = [
      ...fixtures.map((f) => ({ name: f, content: read(f) })),
      { name: 'mailbox.mbox', content: mbox, type: 'application/mbox' },
      { name: 'not-an-email.exe', content: Buffer.from([0x4d, 0x5a, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00]), type: 'application/octet-stream' },
      { name: 'empty.eml', content: Buffer.alloc(0) },
      { name: 'copy-of-paypal.eml', content: read('paypal-lookalike-credential.eml') },
      { name: '../../../etc/passwd', content: read('fake-reply-invoice.eml') },
    ];
    const mp = multipart(files, { note: 'Exported from the complainant mailbox' });
    const r = await admin.call('POST', `/api/cases/${caseId}/batches`, mp.payload, mp.headers);
    expect(r.status).toBe(201);
    const body = r.json();
    batchId = body.batchId;
    expect(body.rejected).toBe(2);
    const byName = Object.fromEntries(body.evidence.map((e: { originalName: string }) => [e.originalName, e]));
    expect(byName['not-an-email.exe'].error.code).toBe('binary-not-email');
    expect(byName['empty.eml'].error.code).toBe('empty-file');
    expect(byName['copy-of-paypal.eml'].status).toBe('duplicate');
    // The multipart parser keeps only the base name of "../../../etc/passwd"; files are stored under
    // their hash in any case. Its bytes equal another file in the batch: a file-level duplicate.
    expect(byName['passwd'].status).toBe('duplicate');
    expect(byName['passwd'].duplicateOf).toBe(byName['fake-reply-invoice.eml'].id);
    expect(byName['paypal-lookalike-credential.eml'].sha256).toMatch(/^[0-9a-f]{64}$/);
  });

  it('processes every message to completion and reports progress', async () => {
    await waitFor(async () => (await admin.call('GET', `/api/cases/${caseId}/progress`)).json().done === true, 180_000);
    const prog = (await admin.call('GET', `/api/cases/${caseId}/progress`)).json();
    // 14 fixtures + 2 mbox members, one of which duplicates legit-newsletter.eml
    expect(prog.messages.analyzed).toBe(15);
    expect(prog.messages.duplicate).toBe(1);
    expect(prog.messages.failed).toBe(0);
    expect(prog.correlation.correlatedAt).not.toBeNull();
  }, 200_000);

  it('lists results with classes consistent with the engine fixtures', async () => {
    const list = (await admin.call('GET', `/api/cases/${caseId}/messages?pageSize=100`)).json();
    expect(list.total).toBe(16);
    const by = (subject: string): { class: string; status: string } => list.items.find((m: { subject: string }) => m.subject === subject);
    expect(by('Action required: your account has been limited').class).toBe('malicious');
    expect(by('Your Monday reading list: 7 stories').class).toBe('benign');
    const filtered = (await admin.call('GET', `/api/cases/${caseId}/messages?class=malicious`)).json();
    expect(filtered.items.every((m: { class: string }) => m.class === 'malicious')).toBe(true);
    expect(filtered.total).toBeGreaterThanOrEqual(8);
  });

  it('serves a full investigation view of one message with provenance and documented findings', async () => {
    const list = (await admin.call('GET', `/api/cases/${caseId}/messages?q=${encodeURIComponent('account has been limited')}`)).json();
    const id = list.items[0].id;
    const d = (await admin.call('GET', `/api/cases/${caseId}/messages/${id}`)).json();
    expect(d.provenance.evidenceSha256).toMatch(/^[0-9a-f]{64}$/);
    expect(d.provenance.derivation).toBe('original');
    expect(d.report.classification.class).toBe('malicious');
    expect(Object.keys(d.findingDocs).length).toBeGreaterThan(3);
    expect(d.processing.engineVersion).toBe('1.1.0');
    expect(d.history.map((h: { kind: string }) => h.kind)).toEqual(expect.arrayContaining(['queued', 'analysis-started', 'analyzed']));
    const raw = (await admin.call('GET', `/api/cases/${caseId}/messages/${id}/raw`)).json();
    expect(raw.headers.find((h: { name: string }) => h.name === 'From')).toBeDefined();
    expect(raw.text.slice(raw.headers[0].start, raw.headers[0].end)).toMatch(/^Delivered-To:/);
  });

  it('extracts the mbox members with offsets and links duplicates instead of re-analysing', async () => {
    const list = (await admin.call('GET', `/api/cases/${caseId}/messages?status=duplicate`)).json();
    expect(list.items).toHaveLength(1);
    for (const m of list.items) expect(m.duplicateOf).toBeTruthy();
    const lunch = (await admin.call('GET', `/api/cases/${caseId}/messages?q=Lunch`)).json().items[0];
    expect(lunch.derivation).toBe('extracted-from-mbox');
  });

  it('correlates the rotated SharePoint campaign into one cluster', async () => {
    const clusters = (await admin.call('GET', `/api/cases/${caseId}/clusters`)).json();
    const sp = clusters.find((c: { size: number; label: string }) => c.size >= 4);
    expect(sp).toBeDefined();
    const detail = (await admin.call('GET', `/api/cases/${caseId}/clusters/${sp.id}`)).json();
    expect(detail.messages.every((m: { subject: string }) => /shared .*Salary Adjustment/i.test(m.subject))).toBe(true);
    expect(detail.relationships.length).toBeGreaterThan(0);
    expect(detail.profile.rotated.map((r: { label: string }) => r.label)).toContain('Sender domain');
  });

  it('builds a graph of real entities whose edges all point at existing nodes', async () => {
    const g = (await admin.call('GET', `/api/cases/${caseId}/graph`)).json();
    const ids = new Set(g.nodes.map((n: { id: string }) => n.id));
    expect(g.nodes.some((n: { kind: string }) => n.kind === 'message')).toBe(true);
    expect(g.nodes.some((n: { kind: string }) => n.kind === 'cluster')).toBe(true);
    for (const e of g.edges) {
      expect(ids.has(e.source)).toBe(true);
      expect(ids.has(e.target)).toBe(true);
      expect(e.evidence.length).toBeGreaterThan(0);
    }
    const limited = (await admin.call('GET', `/api/cases/${caseId}/graph?limit=20`)).json();
    expect(limited.nodes.length).toBeLessThanOrEqual(20);
    expect(Object.values(limited.hidden).reduce((s: number, n) => s + (n as number), 0)).toBeGreaterThan(0);
    expect(limited.hiddenReason).toMatch(/highest-priority/);
  });

  it('lists indicators with roles and opens an indicator investigation', async () => {
    const ind = (await admin.call('GET', `/api/cases/${caseId}/indicators?q=paypa1-secure.com`)).json();
    expect(ind.items.length).toBeGreaterThan(0);
    const d = (await admin.call('GET', `/api/cases/${caseId}/indicators/${ind.items[0].id}`)).json();
    expect(d.observations.length).toBeGreaterThan(0);
    expect(d.observations[0].ref).toBeTruthy();
  });
});

describe('reports', () => {
  const generate = async (format: string): Promise<{ id: string; dataSha256: string; fileSha256: string }> => {
    const r = await admin.call('POST', `/api/cases/${caseId}/reports`, { format, scope: 'case' });
    expect(r.status).toBe(201);
    return r.json();
  };

  it('produces a schema-valid JSON report whose data hash verifies', async () => {
    const meta = await generate('json');
    const dl = await admin.call('GET', `/api/cases/${caseId}/reports/${meta.id}/download`);
    expect(dl.status).toBe(200);
    const report = JSON.parse(dl.body) as ForensicReport;
    const ajv = new Ajv2020({ allErrors: true, strict: false });
    const validate = ajv.compile(REPORT_JSON_SCHEMA as object);
    expect(validate(report), JSON.stringify(validate.errors?.slice(0, 3))).toBe(true);
    expect(verifyReportHash(report)).toBe(true);
    expect(report.integrity.dataSha256).toBe(meta.dataSha256);
    expect(report.statistics.messages).toBe(16);
    expect(report.evidence.find((e) => e.originalName === 'not-an-email.exe')?.status).toBe('rejected');
    const mal = report.messages.find((m) => m.classification?.class === 'malicious');
    expect(mal?.findings.some((f) => f.method && f.recommendedActions.length)).toBe(true);
    expect(dl.headers['x-report-sha256']).toBe(meta.fileSha256);
  });

  it('renders Markdown and DOCX from the same data (same counts, defanged indicators)', async () => {
    const md = await generate('md');
    const mdText = (await admin.call('GET', `/api/cases/${caseId}/reports/${md.id}/download`)).body;
    expect(mdText).toContain('Operation Test Kitchen');
    expect(mdText).toMatch(/paypa1-secure\[\.\]com/);
    expect(mdText).not.toMatch(/https:\/\/paypa1-secure\.com/);
    const docx = await generate('docx');
    const bin = (await admin.call('GET', `/api/cases/${caseId}/reports/${docx.id}/download`)).raw;
    const files = unzipSync(new Uint8Array(bin));
    const xml = strFromU8(files['word/document.xml'] as Uint8Array);
    expect(xml).toContain('Operation Test Kitchen');
    expect(xml).toContain(docx.dataSha256);
    // The three renderings were generated separately but describe the same evidence.
    const json = JSON.parse((await admin.call('GET', `/api/cases/${caseId}/reports/${(await generate('json')).id}/download`)).body) as ForensicReport;
    const malicious = json.statistics.byClass['malicious'] ?? 0;
    expect(mdText).toContain(`| Classified malicious | ${malicious} |`);
  });
});

describe('access control and limits', () => {
  const other = (): Client => new Client(p.app);

  it('hides cases from non-members and enforces read-only roles', async () => {
    const created = await admin.call('POST', '/api/users', { username: 'analyst', displayName: 'Analyst', password: PASSWORD, role: 'investigator' });
    expect(created.status).toBe(200);
    const c = other();
    await c.login('analyst', PASSWORD);
    expect((await c.call('GET', `/api/cases/${caseId}`)).status).toBe(404);
    expect((await c.call('GET', `/api/cases/${caseId}/messages`)).status).toBe(404);
    expect((await admin.call('POST', `/api/cases/${caseId}/members`, { userId: created.json().id, role: 'viewer' })).status).toBe(200);
    expect((await c.call('GET', `/api/cases/${caseId}`)).status).toBe(200);
    const mp = multipart([{ name: 'x.eml', content: read('legit-newsletter.eml') }]);
    expect((await c.call('POST', `/api/cases/${caseId}/batches`, mp.payload, mp.headers)).status).toBe(403);
    expect((await c.call('DELETE', `/api/cases/${caseId}`, { confirm: 'Operation Test Kitchen' })).status).toBe(403);
  });

  it('rejects a batch of 101 files atomically', async () => {
    const before = (await admin.call('GET', `/api/cases/${caseId}/evidence`)).json().length;
    const mp = multipart(Array.from({ length: 101 }, (_, i) => ({ name: `m${i}.eml`, content: `From: a${i}@example.org\r\nSubject: s${i}\r\n\r\nbody ${i}\r\n` })));
    const r = await admin.call('POST', `/api/cases/${caseId}/batches`, mp.payload, mp.headers);
    expect(r.status).toBe(413);
    expect(r.json().error.code).toBe('too-many-files');
    expect((await admin.call('GET', `/api/cases/${caseId}/evidence`)).json().length).toBe(before);
  });

  it('accepts exactly 100 files', async () => {
    const c = await admin.call('POST', '/api/cases', { name: 'Limits' });
    const id = c.json().id;
    const mp = multipart(Array.from({ length: 100 }, (_, i) => ({ name: `m${i}.eml`, content: `From: Sender ${i} <s${i}@example.org>\r\nTo: v@example.org\r\nSubject: Note ${i}\r\nDate: Mon, 21 Sep 2026 10:00:00 +0000\r\nMessage-ID: <n${i}@example.org>\r\n\r\nPlain note number ${i}.\r\n` })));
    const r = await admin.call('POST', `/api/cases/${id}/batches`, mp.payload, mp.headers);
    expect(r.status).toBe(201);
    expect(r.json().accepted).toBe(100);
    await waitFor(async () => (await admin.call('GET', `/api/cases/${id}/progress`)).json().done === true, 240_000);
    const prog = (await admin.call('GET', `/api/cases/${id}/progress`)).json();
    expect(prog.messages.analyzed).toBe(100);
  }, 260_000);

  it('verifies stored evidence and the audit chain', async () => {
    const ev = (await admin.call('GET', `/api/cases/${caseId}/evidence`)).json().find((e: { status: string }) => e.status === 'expanded');
    const v = (await admin.call('POST', `/api/cases/${caseId}/evidence/${ev.id}/verify`, {})).json();
    expect(v.ok).toBe(true);
    const audit = (await admin.call('GET', '/api/admin/audit/verify')).json();
    expect(audit.ok).toBe(true);
    const actions = (await admin.call('GET', `/api/cases/${caseId}/activity`)).json().audit.map((a: { action: string }) => a.action);
    expect(actions).toEqual(expect.arrayContaining(['case.created', 'evidence.uploaded', 'report.generated', 'report.downloaded', 'message.raw-viewed']));
  });

  it('refuses to delete a case under legal hold, then deletes it and its stored files', async () => {
    const c = (await admin.call('POST', '/api/cases', { name: 'Disposable' })).json();
    const mp = multipart([{ name: 'unique.eml', content: 'From: z@example.org\r\nSubject: unique to this case\r\nMessage-ID: <u@example.org>\r\n\r\nonly here\r\n' }]);
    const up = (await admin.call('POST', `/api/cases/${c.id}/batches`, mp.payload, mp.headers)).json();
    const sha = up.evidence[0].sha256;
    expect(p.ctx.store.exists('evidence', sha)).toBe(true);
    await admin.call('PATCH', `/api/cases/${c.id}`, { legalHold: true });
    expect((await admin.call('DELETE', `/api/cases/${c.id}`, { confirm: 'Disposable' })).status).toBe(409);
    await admin.call('PATCH', `/api/cases/${c.id}`, { legalHold: false });
    expect((await admin.call('DELETE', `/api/cases/${c.id}`, { confirm: 'wrong name' })).status).toBe(400);
    await waitFor(async () => (await admin.call('GET', `/api/cases/${c.id}/progress`)).json().done === true, 60_000);
    expect((await admin.call('DELETE', `/api/cases/${c.id}`, { confirm: 'Disposable' })).status).toBe(200);
    expect(p.ctx.store.exists('evidence', sha)).toBe(false);
    expect((await admin.call('GET', `/api/cases/${c.id}`)).status).toBe(404);
  }, 90_000);
});

describe('resilience', () => {
  it('resumes jobs interrupted by a restart', async () => {
    const c = (await admin.call('POST', '/api/cases', { name: 'Restart' })).json();
    await p.ctx.processor.stop();
    const mp = multipart([{ name: 'r.eml', content: read('bec-giftcard-replyto.eml') }]);
    await admin.call('POST', `/api/cases/${c.id}/batches`, mp.payload, mp.headers);
    // Simulate a crash mid-flight: the job is marked running but nothing is processing it.
    p.ctx.db.run("UPDATE jobs SET status = 'running', attempts = 1 WHERE case_id = ? AND status = 'queued'", c.id);
    const { Processor } = await import('../server/analysis/processor');
    const fresh = new Processor({ cfg: p.ctx.cfg, db: p.ctx.db, queue: p.ctx.queue, pool: p.ctx.pool, intelDbPath: null, caseDbPath: p.ctx.caseDbPath, log: () => undefined });
    fresh.start();
    await waitFor(async () => (await admin.call('GET', `/api/cases/${c.id}/progress`)).json().messages.analyzed === 1, 60_000);
    const events = p.ctx.db.all<{ kind: string }>("SELECT kind FROM events WHERE case_id = ? AND subject_type = 'evidence'", c.id).map((e) => e.kind);
    expect(events).toEqual(expect.arrayContaining(['received', 'resumed-after-interruption', 'expanded']));
    await fresh.stop();
  }, 90_000);

  it('isolates failures: a message that cannot be analysed in time fails alone, with a recorded reason', async () => {
    const slow = await startPlatform((cfg) => {
      cfg.analysisTimeoutMs = 1;
    });
    try {
      const c = new Client(slow.app);
      await c.call('POST', '/api/setup', { token: slow.ctx.setupToken, username: 'admin', password: PASSWORD, displayName: 'A' });
      await c.login('admin', PASSWORD);
      const cs = (await c.call('POST', '/api/cases', { name: 'Timeouts' })).json();
      const mp = multipart([{ name: 'a.eml', content: read('macro-invoice.eml') }, { name: 'junk.bin', content: Buffer.from([0, 1, 2, 3, 0, 0, 0]) }]);
      const up = (await c.call('POST', `/api/cases/${cs.id}/batches`, mp.payload, mp.headers)).json();
      expect(up.rejected).toBe(1);
      await waitFor(async () => (await c.call('GET', `/api/cases/${cs.id}/progress`)).json().done === true, 120_000);
      const list = (await c.call('GET', `/api/cases/${cs.id}/messages`)).json();
      expect(list.items[0].status).toBe('failed');
      expect(list.items[0].error.code).toBe('timeout');
      const hist = (await c.call('GET', `/api/cases/${cs.id}/messages/${list.items[0].id}/history`)).json();
      expect(hist.filter((h: { kind: string }) => h.kind === 'retry-scheduled').length).toBe(2);
    } finally {
      await slow.close();
    }
  }, 150_000);
});
