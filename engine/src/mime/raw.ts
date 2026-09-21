// Low-level RFC 5322 / MIME helpers operating on the raw message (Latin-1 string = 1 char per byte).
// postal-mime handles decoding of bodies & attachments; this module keeps what it abstracts away:
// exact header order, duplicates, folding, and the MIME tree shape (forensic signal).
import { decodeWords } from 'postal-mime';
import type { HeaderEntry, MimePart } from '../types';

const utf8 = new TextDecoder('utf-8', { fatal: false });

export interface SplitMessage {
  headerBlock: string;
  body: string;
}

export function splitMessage(raw: string): SplitMessage {
  const m = /\r?\n\r?\n/.exec(raw);
  if (!m) return { headerBlock: raw, body: '' };
  return { headerBlock: raw.slice(0, m.index), body: raw.slice(m.index + m[0].length) };
}

/** Re-interpret a Latin-1 string's bytes as UTF-8 (headers sent raw with SMTPUTF8). */
function latin1AsUtf8(s: string): string {
  // eslint-disable-next-line no-control-regex
  if (!/[\x80-\xff]/.test(s)) return s;
  const bytes = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) bytes[i] = s.charCodeAt(i) & 0xff;
  return utf8.decode(bytes);
}

export interface RawHeader {
  name: string; // original case
  key: string; // lowercase
  value: string; // unfolded, undecoded
}

export function parseHeaderBlock(block: string): { headers: RawHeader[]; malformed: number } {
  const headers: RawHeader[] = [];
  let malformed = 0;
  const lines = block.split(/\r?\n/);
  for (const line of lines) {
    if (/^[ \t]/.test(line) && headers.length) {
      const last = headers[headers.length - 1] as RawHeader;
      last.value += ' ' + line.trim();
      continue;
    }
    if (!line.trim()) continue;
    const idx = line.indexOf(':');
    if (idx <= 0 || /\s/.test(line.slice(0, idx).trim()) || idx > 76) {
      if (!/^From /.test(line)) malformed++;
      continue;
    }
    const name = line.slice(0, idx).trim();
    headers.push({ name, key: name.toLowerCase(), value: line.slice(idx + 1).trim() });
  }
  return { headers, malformed };
}

export function decodeHeaderValue(value: string): string {
  try {
    return decodeWords(latin1AsUtf8(value)).replace(/\s+/g, ' ').trim();
  } catch {
    return latin1AsUtf8(value);
  }
}

export function toHeaderEntries(headers: RawHeader[]): HeaderEntry[] {
  return headers.map((h) => ({ name: h.name, value: decodeHeaderValue(h.value) }));
}

export function headerValues(headers: RawHeader[], key: string): string[] {
  return headers.filter((h) => h.key === key).map((h) => h.value);
}

export function firstHeader(headers: RawHeader[], key: string): string | null {
  const h = headers.find((x) => x.key === key);
  return h ? h.value : null;
}

// ── Structured header parameters (Content-Type, Content-Disposition, DKIM tags) ──

export interface ParsedParams {
  value: string;
  params: Record<string, string>;
}

export function parseParams(header: string): ParsedParams {
  const params: Record<string, string> = {};
  const i = header.indexOf(';');
  const value = (i < 0 ? header : header.slice(0, i)).trim().toLowerCase();
  if (i < 0) return { value, params };
  const rest = header.slice(i + 1);
  const re = /\s*([^=;\s]+)\s*=\s*(?:"((?:[^"\\]|\\.)*)"|([^;]*))\s*;?/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(rest))) {
    const key = (m[1] as string).toLowerCase();
    const val = m[2] !== undefined ? m[2].replace(/\\(.)/g, '$1') : (m[3] ?? '').trim();
    // RFC 2231 continuations: name*0*=, name*1*= …
    const base = key.replace(/\*\d*\*?$/, '');
    if (base !== key) {
      let v = val;
      if (/\*$/.test(key)) {
        const enc = /^([^']*)'[^']*'(.*)$/.exec(v);
        if (enc) v = enc[2] as string;
        try {
          v = decodeURIComponent(v);
        } catch {
          /* keep raw */
        }
      }
      params[base] = (params[base] ?? '') + v;
    } else {
      params[key] = val;
    }
    if (re.lastIndex >= rest.length) break;
  }
  return { value, params };
}

// ── MIME tree walk ──────────────────────────────────────────────────────────

export interface MimeWalk {
  parts: MimePart[];
  anomalies: string[];
}

const MAX_PARTS = 400;
const MAX_DEPTH = 24;

export function walkMime(raw: string): MimeWalk {
  const parts: MimePart[] = [];
  const anomalies = new Set<string>();

  const visit = (segment: string, depth: number): void => {
    if (parts.length >= MAX_PARTS) {
      anomalies.add('too-many-parts');
      return;
    }
    if (depth > MAX_DEPTH) {
      anomalies.add('excessive-nesting');
      return;
    }
    const { headerBlock, body } = splitMessage(segment);
    const { headers } = parseHeaderBlock(headerBlock);
    const ctRaw = firstHeader(headers, 'content-type') ?? 'text/plain';
    const ct = parseParams(ctRaw);
    const cte = firstHeader(headers, 'content-transfer-encoding');
    const cd = firstHeader(headers, 'content-disposition');
    const cdp = cd ? parseParams(cd) : null;
    const filename = cdp?.params['filename'] ?? ct.params['name'] ?? null;
    parts.push({
      contentType: ct.value || 'text/plain',
      depth,
      encoding: cte ? cte.trim().toLowerCase() : null,
      charset: ct.params['charset']?.toLowerCase() ?? null,
      filename: filename ? decodeHeaderValue(filename) : null,
      size: body.length,
    });

    if (ct.value.startsWith('multipart/')) {
      const boundary = ct.params['boundary'];
      if (!boundary) {
        anomalies.add('multipart-without-boundary');
        return;
      }
      const delim = '--' + boundary;
      const lines = body.split(/\r?\n/);
      let current: string[] | null = null;
      let closed = false;
      const children: string[] = [];
      for (const line of lines) {
        const t = line.replace(/[ \t]+$/, '');
        if (t === delim) {
          if (current) children.push(current.join('\n'));
          current = [];
          continue;
        }
        if (t === delim + '--') {
          if (current) children.push(current.join('\n'));
          current = null;
          closed = true;
          break;
        }
        if (current) current.push(line);
      }
      if (current && current.length) children.push(current.join('\n'));
      if (children.length === 0) anomalies.add('boundary-not-found');
      if (!closed && children.length) anomalies.add('unterminated-multipart');
      for (const child of children) visit(child, depth + 1);
    } else if (ct.value === 'message/rfc822' && depth < 3) {
      visit(body, depth + 1);
    }
  };

  visit(raw, 0);
  return { parts, anomalies: [...anomalies] };
}
