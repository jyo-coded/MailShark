// DKIM verification (RFC 6376, RFC 8463 for Ed25519).
//
// Offline, from the evidence alone: canonicalise the body and compare its hash with the signed
// body hash (bh=). A match proves the body is byte-for-byte what the signing domain signed (or the
// first l= octets of it). A mismatch means the body changed after signing: in transit (mailing-list
// footers, gateway link rewriting), in the mailbox (e.g. Safe Links), or by tampering.
//
// With a key resolver (DNS TXT lookup supplied by the host): verify the header signature (b=).
// The signing key is fetched *now*, so a key rotated or revoked since delivery makes an old genuine
// signature unverifiable. That outcome is reported as such, never as a failure.
import type { DkimVerification, DkimKeyResolver } from '../types';

const MAX_SIGNATURES = 5;

/** One header field exactly as it appears in the message (folding preserved, no final CRLF). */
interface RawField {
  name: string; // lowercase
  raw: string;
}

/** Normalise line endings to CRLF: DKIM is defined over the canonical (CRLF) form. */
export function toCrlf(raw: string): string {
  return raw.replace(/\r?\n/g, '\r\n');
}

export function splitHeaderBody(crlf: string): { header: string; body: string } {
  const i = crlf.indexOf('\r\n\r\n');
  if (i < 0) return { header: crlf, body: '' };
  return { header: crlf.slice(0, i), body: crlf.slice(i + 4) };
}

export function rawFields(header: string): RawField[] {
  const out: RawField[] = [];
  for (const line of header.split('\r\n')) {
    if (/^[ \t]/.test(line) && out.length) {
      (out[out.length - 1] as RawField).raw += '\r\n' + line;
      continue;
    }
    const idx = line.indexOf(':');
    if (idx <= 0) continue; // mbox "From " separator or garbage
    out.push({ name: line.slice(0, idx).trim().toLowerCase(), raw: line });
  }
  return out;
}

export function canonBodySimple(body: string): string {
  const lines = body.split('\r\n');
  while (lines.length && lines[lines.length - 1] === '') lines.pop();
  return lines.length ? lines.join('\r\n') + '\r\n' : '\r\n';
}

export function canonBodyRelaxed(body: string): string {
  const lines = body.split('\r\n').map((l) => l.replace(/[ \t]+/g, ' ').replace(/ $/, ''));
  while (lines.length && lines[lines.length - 1] === '') lines.pop();
  return lines.length ? lines.join('\r\n') + '\r\n' : '';
}

export function canonHeaderRelaxed(raw: string): string {
  const idx = raw.indexOf(':');
  const name = raw.slice(0, idx).trim().toLowerCase();
  const value = raw
    .slice(idx + 1)
    .replace(/\r\n(?=[ \t])/g, '')
    .replace(/[ \t]+/g, ' ')
    .trim();
  return `${name}:${value}\r\n`;
}

function canonHeader(raw: string, mode: 'simple' | 'relaxed'): string {
  return mode === 'relaxed' ? canonHeaderRelaxed(raw) : raw + '\r\n';
}

/** Tag-list parser (RFC 6376 §3.2). Values keep inner FWS except where the tag forbids it. */
export function parseTagList(value: string): Record<string, string> {
  const tags: Record<string, string> = {};
  for (const part of value.split(';')) {
    const i = part.indexOf('=');
    if (i < 0) continue;
    const k = part.slice(0, i).replace(/\s+/g, '').toLowerCase();
    if (!k || k in tags) continue; // duplicate tags make a signature invalid; keep the first
    tags[k] = part.slice(i + 1).replace(/\r\n[ \t]/g, ' ').trim();
  }
  return tags;
}

/** Empty the b= value (the signature itself) in the raw header, keeping everything else intact. */
export function stripSignatureValue(raw: string): string {
  const idx = raw.indexOf(':');
  return raw.slice(0, idx + 1) + raw.slice(idx + 1).replace(/(^|;)([ \t\r\n]*b[ \t\r\n]*=)[^;]*/, '$1$2');
}

function b64ToBytes(b64: string): Uint8Array | null {
  try {
    const bin = atob(b64.replace(/\s+/g, ''));
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  } catch {
    return null;
  }
}

function bytesToB64(bytes: Uint8Array): string {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i] as number);
  return btoa(s);
}

function latin1Bytes(s: string): Uint8Array {
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i) & 0xff;
  return out;
}

function toBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}

async function digest(alg: 'SHA-256' | 'SHA-1', data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest(alg, toBuffer(data)));
}

// ── DER helpers: some DNS records publish a bare PKCS#1 RSAPublicKey instead of SPKI ──

function derLength(n: number): number[] {
  if (n < 0x80) return [n];
  const bytes: number[] = [];
  while (n > 0) {
    bytes.unshift(n & 0xff);
    n >>= 8;
  }
  return [0x80 | bytes.length, ...bytes];
}

function pkcs1ToSpki(pkcs1: Uint8Array): Uint8Array {
  const algId = [0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00];
  const bitString = [0x03, ...derLength(pkcs1.length + 1), 0x00, ...pkcs1];
  const body = [...algId, ...bitString];
  return new Uint8Array([0x30, ...derLength(body.length), ...body]);
}

interface ImportedKey {
  key: CryptoKey;
  bits: number | null;
}

async function importRsaKey(der: Uint8Array, hash: 'SHA-256' | 'SHA-1'): Promise<ImportedKey | null> {
  const algo = { name: 'RSASSA-PKCS1-v1_5', hash };
  for (const candidate of [der, pkcs1ToSpki(der)]) {
    try {
      const key = await crypto.subtle.importKey('spki', toBuffer(candidate), algo, false, ['verify']);
      const bits = (key.algorithm as { modulusLength?: number }).modulusLength ?? null;
      return { key, bits };
    } catch {
      /* try the next encoding */
    }
  }
  return null;
}

export interface DkimInputs {
  /** The whole raw message as a Latin-1 string (one char per byte). */
  raw: string;
  /** Lowercase address(es) the message was delivered to, for the replay heuristic. */
  recipients: string[];
  /** Time the receiving server accepted the message (epoch ms), if known. */
  receivedAt: number | null;
  resolveKey?: DkimKeyResolver | null;
}

export async function verifyDkim(input: DkimInputs): Promise<DkimVerification[]> {
  const crlf = toCrlf(input.raw);
  const { header, body } = splitHeaderBody(crlf);
  const fields = rawFields(header);
  const sigFields = fields.filter((f) => f.name === 'dkim-signature').slice(0, MAX_SIGNATURES);
  if (!sigFields.length) return [];

  const bodyCanon: Record<'simple' | 'relaxed', string | null> = { simple: null, relaxed: null };
  const out: DkimVerification[] = [];

  for (const sigField of sigFields) {
    const tags = parseTagList(sigField.raw.slice(sigField.raw.indexOf(':') + 1));
    const domain = (tags['d'] ?? '').toLowerCase();
    const selector = (tags['s'] ?? '').toLowerCase();
    const algorithm = (tags['a'] ?? '').toLowerCase();
    const [hc, bc] = (tags['c'] ?? 'simple/simple').toLowerCase().split('/');
    const headerMode: 'simple' | 'relaxed' = hc === 'relaxed' ? 'relaxed' : 'simple';
    const bodyMode: 'simple' | 'relaxed' = (bc ?? 'simple') === 'relaxed' ? 'relaxed' : 'simple';
    const signedHeaders = (tags['h'] ?? '')
      .replace(/\s+/g, '')
      .toLowerCase()
      .split(':')
      .filter(Boolean);
    const l = tags['l'] !== undefined && /^\d+$/.test(tags['l'].replace(/\s+/g, '')) ? Number(tags['l'].replace(/\s+/g, '')) : null;
    const t = tags['t'] !== undefined && /^\d+$/.test(tags['t'].trim()) ? Number(tags['t'].trim()) * 1000 : null;
    const x = tags['x'] !== undefined && /^\d+$/.test(tags['x'].trim()) ? Number(tags['x'].trim()) * 1000 : null;

    const v: DkimVerification = {
      domain,
      selector,
      algorithm,
      canonicalization: `${headerMode}/${bodyMode}`,
      signedHeaders,
      coversFrom: signedHeaders.includes('from'),
      fromOversigned: signedHeaders.filter((h) => h === 'from').length > fields.filter((f) => f.name === 'from').length,
      bodyLengthLimit: l,
      bodyBeyondLimit: null,
      signedAt: t,
      expiresAt: x,
      expiredAtReceipt: x !== null && input.receivedAt !== null ? input.receivedAt > x : null,
      signatureAgeAtReceiptSec: t !== null && input.receivedAt !== null ? Math.round((input.receivedAt - t) / 1000) : null,
      recipientInSignedHeaders: null,
      bodyHash: 'not-checked',
      signature: 'not-checked',
      keyBits: null,
      keyTesting: null,
      detail: '',
    };

    const malformed = !domain || !selector || !tags['bh'] || !tags['b'] || !signedHeaders.length || (tags['v'] ?? '1').trim() !== '1';
    const hashAlg: 'SHA-256' | 'SHA-1' | null = algorithm === 'rsa-sha256' || algorithm === 'ed25519-sha256' ? 'SHA-256' : algorithm === 'rsa-sha1' ? 'SHA-1' : null;
    if (malformed || !hashAlg) {
      v.bodyHash = 'error';
      v.signature = malformed ? 'error' : 'unsupported';
      v.detail = malformed ? 'Signature header is missing required tags (v, d, s, h, bh, b).' : `Unsupported algorithm "${algorithm}".`;
      out.push(v);
      continue;
    }

    // ── Body hash (offline) ──
    let canon = bodyCanon[bodyMode];
    if (canon === null) {
      canon = bodyMode === 'relaxed' ? canonBodyRelaxed(body) : canonBodySimple(body);
      bodyCanon[bodyMode] = canon;
    }
    let hashed = canon;
    if (l !== null) {
      v.bodyBeyondLimit = canon.length > l;
      hashed = canon.slice(0, l);
    }
    const bh = bytesToB64(await digest(hashAlg, latin1Bytes(hashed)));
    v.bodyHash = bh === (tags['bh'] as string).replace(/\s+/g, '') ? 'pass' : 'fail';

    // Was the actual recipient part of what the domain signed? (DKIM replay detection)
    if (input.recipients.length) {
      const signedRcpt = signedHeaders.filter((h) => h === 'to' || h === 'cc');
      if (signedRcpt.length) {
        const values = fields.filter((f) => f.name === 'to' || f.name === 'cc').map((f) => f.raw.toLowerCase());
        v.recipientInSignedHeaders = input.recipients.some((r) => values.some((val) => val.includes(r.toLowerCase())));
      }
    }

    // ── Header signature (needs the public key) ──
    if (!input.resolveKey) {
      v.detail = v.bodyHash === 'pass' ? 'Body hash verified offline; signature not checked (no key lookup).' : 'Body hash does not match the signed value.';
      out.push(v);
      continue;
    }
    let record: string | null;
    try {
      record = await input.resolveKey(selector, domain);
    } catch (e) {
      v.signature = 'key-unavailable';
      v.detail = `Key lookup failed: ${e instanceof Error ? e.message : String(e)}`;
      out.push(v);
      continue;
    }
    if (!record) {
      v.signature = 'key-unavailable';
      v.detail = `No DKIM key published at ${selector}._domainkey.${domain} now; it may have been rotated since the message was sent.`;
      out.push(v);
      continue;
    }
    const keyTags = parseTagList(record);
    const p = (keyTags['p'] ?? '').replace(/\s+/g, '');
    v.keyTesting = /(^|:)\s*y\s*(:|$)/i.test(keyTags['t'] ?? '');
    if (!p) {
      v.signature = 'key-revoked';
      v.detail = 'The selector exists but its key is revoked (empty p=).';
      out.push(v);
      continue;
    }
    const keyBytes = b64ToBytes(p);
    const sigBytes = b64ToBytes(tags['b'] as string);
    if (!keyBytes || !sigBytes) {
      v.signature = 'error';
      v.detail = 'Key or signature is not valid base64.';
      out.push(v);
      continue;
    }

    // Signed data: selected header instances (bottom-up), then the signature header without b=.
    const used = new Map<string, number>();
    let data = '';
    for (const name of signedHeaders) {
      const instances = fields.filter((f) => f.name === name);
      const n = used.get(name) ?? 0;
      const pick = instances[instances.length - 1 - n];
      used.set(name, n + 1);
      if (pick) data += canonHeader(pick.raw, headerMode);
    }
    data += canonHeader(stripSignatureValue(sigField.raw), headerMode).replace(/\r\n$/, '');
    const dataBytes = latin1Bytes(data);

    try {
      const keyType = (keyTags['k'] ?? 'rsa').toLowerCase();
      let ok: boolean;
      if (algorithm === 'ed25519-sha256') {
        if (keyType !== 'ed25519') throw new Error('key type does not match algorithm');
        const key = await crypto.subtle.importKey('raw', toBuffer(keyBytes), { name: 'Ed25519' }, false, ['verify']);
        v.keyBits = 256;
        ok = await crypto.subtle.verify({ name: 'Ed25519' }, key, toBuffer(sigBytes), toBuffer(await digest('SHA-256', dataBytes)));
      } else {
        if (keyType !== 'rsa') throw new Error('key type does not match algorithm');
        const imported = await importRsaKey(keyBytes, hashAlg);
        if (!imported) throw new Error('unreadable RSA key');
        v.keyBits = imported.bits;
        ok = await crypto.subtle.verify({ name: 'RSASSA-PKCS1-v1_5' }, imported.key, toBuffer(sigBytes), toBuffer(dataBytes));
      }
      v.signature = ok ? 'pass' : 'fail';
      v.detail = ok
        ? `Signature by ${domain} verifies against the key currently published at ${selector}._domainkey.${domain}.`
        : `Signature does not verify against the current key: signed headers were altered, or the key was replaced under the same selector.`;
    } catch (e) {
      v.signature = /Ed25519|algorithm|Unrecognized|NotSupported/i.test(String(e)) ? 'unsupported' : 'error';
      v.detail = `Verification could not run: ${e instanceof Error ? e.message : String(e)}`;
    }
    out.push(v);
  }
  return out;
}
