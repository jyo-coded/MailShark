// Evidence formats and the content-addressed store.
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, readdirSync, writeFileSync, chmodSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Readable } from 'node:stream';
import { describe, expect, it } from 'vitest';
import { detectFormat, expand, expandMbox, FormatError } from '../server/evidence/formats';
import { BlobStore, IntegrityError } from '../server/evidence/store';

const FX = join(__dirname, '..', '..', 'fixtures', 'eml');
const fixture = (name: string): Buffer => readFileSync(join(FX, name));
const sha = (b: Uint8Array): string => createHash('sha256').update(b).digest('hex');

describe('format detection (by content, never by extension)', () => {
  it('recognises RFC 5322 messages, mbox and emlx', () => {
    expect(detectFormat(fixture('paypal-lookalike-credential.eml')).format).toBe('eml');
    expect(detectFormat(Buffer.from('From MAILER-DAEMON Fri Jul  8 12:08:34 2011\nFrom: a@b.example\nSubject: x\n\nbody\n')).format).toBe('mbox');
    const emlx = Buffer.concat([Buffer.from('120\n'), fixture('legit-newsletter.eml').subarray(0, 120), Buffer.from('<?xml version="1.0"?><plist></plist>')]);
    expect(detectFormat(emlx).format).toBe('emlx');
  });

  it('rejects files that are not email, with a specific reason', () => {
    const code = (b: Buffer): string => {
      try {
        detectFormat(b);
        return 'accepted';
      } catch (e) {
        return (e as FormatError).code;
      }
    };
    expect(code(Buffer.alloc(0))).toBe('empty-file');
    expect(code(Buffer.from([0x4d, 0x5a, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00]))).toBe('binary-not-email');
    expect(code(Buffer.from('﻿From: a@b\r\n', 'utf16le'))).toBe('unsupported-encoding');
    expect(code(Buffer.from([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1, 0, 0, 0, 0]))).toBe('ole-not-msg');
    expect(code(Buffer.from('<html><body>not an email</body></html>'))).toBe('unsupported-format');
    expect(code(Buffer.from('just some text\nwithout headers\n'))).toBe('unsupported-format');
  });
});

describe('container expansion', () => {
  const a = fixture('legit-newsletter.eml');
  const mbox = Buffer.concat([
    Buffer.from('From sender@example.org Mon Sep 21 15:48:59 2026\n'),
    a,
    Buffer.from('\nFrom sender@example.org Mon Sep 21 15:49:59 2026\n'),
    // mboxrd escaping: a body line ">From the desk…" was written as ">>From the desk…"
    Buffer.from('From: Support <support@example.org>\nTo: v@example.org\nSubject: escaped\n\nHello\n>>From the desk of support\nBye\n'),
    Buffer.from('\n'),
  ]);

  it('splits mbox members, records byte offsets and undoes mboxrd escaping', () => {
    const exp = expandMbox(new Uint8Array(mbox), 100);
    expect(exp.messages).toHaveLength(2);
    expect(exp.messages[0]?.offset).toBe(0);
    expect(exp.messages[1]?.offset).toBe(mbox.indexOf('From sender@example.org Mon Sep 21 15:49:59'));
    expect(Buffer.from(exp.messages[0]?.bytes ?? []).equals(a)).toBe(true);
    expect(Buffer.from(exp.messages[1]?.bytes ?? []).toString('latin1')).toContain('\n>From the desk of support');
    expect(exp.messages.every((m) => m.derivation === 'extracted-from-mbox')).toBe(true);
  });

  it('caps the number of extracted messages and says so', () => {
    const exp = expandMbox(new Uint8Array(mbox), 1);
    expect(exp.messages).toHaveLength(1);
    expect(exp.truncated).toBe(true);
    expect(exp.notes[0]).toMatch(/only the first 1/);
  });

  it('keeps an .eml byte-identical (original evidence, no derivation)', () => {
    const exp = expand(new Uint8Array(a), 'eml', 10);
    expect(exp.messages[0]?.derivation).toBe('original');
    expect(sha(exp.messages[0]?.bytes as Uint8Array)).toBe(sha(a));
  });

  it('extracts the message from an .emlx and ignores the plist trailer', () => {
    const emlx = Buffer.concat([Buffer.from(`${a.length}\n`), a, Buffer.from('<?xml version="1.0"?><plist version="1.0"><dict/></plist>\n')]);
    const exp = expand(new Uint8Array(emlx), 'emlx', 10);
    expect(Buffer.from(exp.messages[0]?.bytes ?? []).equals(a)).toBe(true);
    expect(exp.messages[0]?.notes[0]).toMatch(/plist/);
  });

  it('every fixture is detected and expands to exactly one original message', () => {
    for (const f of readdirSync(FX).filter((x) => x.endsWith('.eml'))) {
      const bytes = fixture(f);
      expect(detectFormat(bytes).format, f).toBe('eml');
      expect(expand(new Uint8Array(bytes), 'eml', 5).messages, f).toHaveLength(1);
    }
  });
});

describe('content-addressed evidence store', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ms-store-'));
  for (const d of ['evidence', 'derived', 'reports', 'tmp']) mkdtempSync(join(dir, d + '-')); // noise dirs must not matter
  const store = new BlobStore(dir);

  it('hashes while ingesting, stores once under the SHA-256, and verifies on read', async () => {
    const bytes = fixture('macro-invoice.eml');
    const r = await store.ingestStream(Readable.from([bytes.subarray(0, 1000), bytes.subarray(1000)]), 10_000_000);
    expect(r.sha256).toBe(sha(bytes));
    expect(r.sha1).toBe(createHash('sha1').update(bytes).digest('hex'));
    expect(r.md5).toBe(createHash('md5').update(bytes).digest('hex'));
    expect((await store.commit('evidence', r.tmpPath, r.sha256)).existed).toBe(false);
    const again = await store.ingestStream(Readable.from([bytes]), 10_000_000);
    expect((await store.commit('evidence', again.tmpPath, again.sha256)).existed).toBe(true);
    expect((await store.read('evidence', r.sha256)).equals(bytes)).toBe(true);
    expect((await store.verify('evidence', r.sha256)).ok).toBe(true);
  });

  it('stops at the size limit without keeping a partial file', async () => {
    const r = await store.ingestStream(Readable.from([Buffer.alloc(5000, 65)]), 1000);
    expect(r.truncated).toBe(true);
    expect(r.tmpPath).toBe('');
  });

  it('detects tampering with stored bytes', async () => {
    const { sha256 } = await store.putBytes('derived', Buffer.from('From: x@y.example\r\n\r\noriginal'));
    const p = store.pathFor('derived', sha256);
    chmodSync(p, 0o644);
    writeFileSync(p, 'From: x@y.example\r\n\r\ntampered');
    await expect(store.read('derived', sha256)).rejects.toBeInstanceOf(IntegrityError);
    expect((await store.verify('derived', sha256)).ok).toBe(false);
  });

  it('refuses anything that is not a SHA-256 as a blob name (no path traversal)', () => {
    expect(() => store.pathFor('evidence', '../../etc/passwd')).toThrow(/invalid blob id/);
    expect(() => store.pathFor('evidence', 'A'.repeat(64))).toThrow(/invalid blob id/);
  });
});
