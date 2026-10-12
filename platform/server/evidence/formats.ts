// Evidence formats. Detection is by content, never by file extension. Containers are expanded into
// message artifacts that keep a provable link to their source (container hash + byte offset).
//
//   eml   RFC 5322 message (.eml, .txt, saved "Show original")
//   emlx  Apple Mail: "<byte count>\n" + RFC 5322 message + XML plist trailer
//   mbox  RFC 4155 mailbox (Google Takeout, Thunderbird, mutt): "From " separated, mboxrd unescaping
//   msg   Outlook OLE compound file: reconstructed into RFC 5322 (clearly marked as a reconstruction)
import { createHash } from 'node:crypto';
import MsgReader from '@kenjiuno/msgreader';

export type EvidenceFormat = 'eml' | 'emlx' | 'mbox' | 'msg';

export class FormatError extends Error {
  constructor(
    readonly code: 'unsupported-format' | 'empty-file' | 'binary-not-email' | 'ole-not-msg' | 'malformed-container' | 'unsupported-encoding' | 'msg-parse-error',
    message: string,
  ) {
    super(message);
  }
}

const HEADER_NAMES = /^(from|to|cc|subject|date|received|message-id|mime-version|return-path|delivered-to|reply-to|sender|content-type|x-[a-z0-9-]+|dkim-signature|authentication-results|arc-[a-z-]+|x-received|list-[a-z-]+|in-reply-to|references|thread-[a-z-]+|importance|user-agent)\s*:/i;
const MBOX_SEPARATOR = /^From \S*.*\b(19|20)\d\d\b/;

function asciiHead(bytes: Uint8Array, n = 8192): string {
  let s = '';
  const len = Math.min(n, bytes.length);
  for (let i = 0; i < len; i++) s += String.fromCharCode(bytes[i] as number);
  return s;
}

function looksLikeHeaderBlock(text: string): boolean {
  const lines = text.split(/\r?\n/);
  let headers = 0;
  let known = 0;
  for (const line of lines.slice(0, 80)) {
    if (line === '') break;
    if (/^[ \t]/.test(line)) continue;
    if (/^[!-9;-~]+:/.test(line)) {
      headers++;
      if (HEADER_NAMES.test(line)) known++;
    } else return false;
  }
  return headers >= 2 && known >= 1;
}

export interface Detection {
  format: EvidenceFormat;
  note: string;
}

export function detectFormat(head: Uint8Array): Detection {
  if (head.length === 0) throw new FormatError('empty-file', 'The file is empty.');
  if (head[0] === 0xd0 && head[1] === 0xcf && head[2] === 0x11 && head[3] === 0xe0) {
    // Outlook items carry MAPI property streams named "__substg1.0_…" (UTF-16LE in the directory).
    const s = asciiHead(head, Math.min(head.length, 65536)).replace(/\0/g, '');
    if (/__substg1\.0_|__properties_version1\.0|__recip_version1\.0/.test(s)) return { format: 'msg', note: 'Outlook item (OLE compound file with MAPI streams)' };
    throw new FormatError('ole-not-msg', 'This is an OLE compound file but not an Outlook message (e.g. a .doc or .xls).');
  }
  if ((head[0] === 0xff && head[1] === 0xfe) || (head[0] === 0xfe && head[1] === 0xff)) {
    throw new FormatError('unsupported-encoding', 'UTF-16 encoded text is not a valid RFC 5322 message; re-export the message as .eml.');
  }
  const text = asciiHead(head);
  const nul = text.slice(0, 4096).indexOf('\0');
  if (nul >= 0) throw new FormatError('binary-not-email', 'The file contains binary data and is not an email message.');
  const firstLine = text.split(/\r?\n/, 1)[0] ?? '';
  if (/^\d{1,12}\s*$/.test(firstLine) && looksLikeHeaderBlock(text.slice(text.indexOf('\n') + 1))) return { format: 'emlx', note: 'Apple Mail .emlx (byte count prefix)' };
  if (MBOX_SEPARATOR.test(firstLine)) return { format: 'mbox', note: 'Unix mailbox (RFC 4155)' };
  const trimmed = text.replace(/^﻿/, '').replace(/^(\r?\n)+/, '');
  if (looksLikeHeaderBlock(trimmed)) return { format: 'eml', note: 'RFC 5322 message' };
  throw new FormatError('unsupported-format', 'The content is not a recognised email format (.eml, .emlx, .mbox or Outlook .msg).');
}

export interface ExtractedMessage {
  index: number;
  /** Byte offset of the message inside its container (null for reconstructions). */
  offset: number | null;
  bytes: Uint8Array;
  derivation: 'original' | 'extracted-from-mbox' | 'extracted-from-emlx' | 'reconstructed-from-msg';
  notes: string[];
}

export interface Expansion {
  messages: ExtractedMessage[];
  truncated: boolean;
  notes: string[];
}

export function expand(bytes: Uint8Array, format: EvidenceFormat, maxMessages: number): Expansion {
  switch (format) {
    case 'eml':
      return { messages: [{ index: 0, offset: 0, bytes, derivation: 'original', notes: [] }], truncated: false, notes: [] };
    case 'emlx':
      return expandEmlx(bytes);
    case 'mbox':
      return expandMbox(bytes, maxMessages);
    case 'msg':
      return { messages: [msgToEml(bytes)], truncated: false, notes: [] };
  }
}

function expandEmlx(bytes: Uint8Array): Expansion {
  let i = 0;
  while (i < bytes.length && bytes[i] !== 0x0a) i++;
  const count = Number(asciiHead(bytes.subarray(0, i)).trim());
  const start = i + 1;
  if (!Number.isFinite(count) || count <= 0 || start + count > bytes.length) throw new FormatError('malformed-container', 'The .emlx byte count does not match the file.');
  const notes = start + count < bytes.length ? ['Apple Mail metadata (plist) after the message was not analysed.'] : [];
  return { messages: [{ index: 0, offset: start, bytes: bytes.subarray(start, start + count), derivation: 'extracted-from-emlx', notes }], truncated: false, notes: [] };
}

/** Splits an mbox on "From " separator lines (start of file or after a blank line) and undoes mboxrd escaping. */
export function expandMbox(bytes: Uint8Array, maxMessages: number): Expansion {
  const starts: number[] = [];
  let lineStart = 0;
  let prevBlank = true;
  for (let i = 0; i <= bytes.length; i++) {
    if (i === bytes.length || bytes[i] === 0x0a) {
      let end = i;
      if (end > lineStart && bytes[end - 1] === 0x0d) end--;
      const isFrom = end - lineStart >= 5 && bytes[lineStart] === 0x46 && bytes[lineStart + 1] === 0x72 && bytes[lineStart + 2] === 0x6f && bytes[lineStart + 3] === 0x6d && bytes[lineStart + 4] === 0x20;
      if (isFrom && prevBlank && MBOX_SEPARATOR.test(asciiHead(bytes.subarray(lineStart, Math.min(end, lineStart + 300)), 300))) starts.push(lineStart);
      prevBlank = end === lineStart;
      lineStart = i + 1;
    }
  }
  if (!starts.length) throw new FormatError('malformed-container', 'No mbox "From " separator lines were found.');
  const truncated = starts.length > maxMessages;
  const messages: ExtractedMessage[] = [];
  for (let m = 0; m < Math.min(starts.length, maxMessages); m++) {
    const from = starts[m] as number;
    const to = m + 1 < starts.length ? (starts[m + 1] as number) : bytes.length;
    let bodyStart = from;
    while (bodyStart < to && bytes[bodyStart] !== 0x0a) bodyStart++;
    bodyStart++;
    let chunk = bytes.subarray(bodyStart, to);
    // The blank line before the next separator belongs to the mbox, not the message.
    let end = chunk.length;
    if (end >= 2 && chunk[end - 1] === 0x0a && chunk[end - 2] === 0x0a) end--;
    else if (end >= 4 && chunk[end - 1] === 0x0a && chunk[end - 2] === 0x0d && chunk[end - 3] === 0x0a && chunk[end - 4] === 0x0d) end -= 2;
    chunk = chunk.subarray(0, end);
    messages.push({ index: m, offset: from, bytes: unescapeMboxrd(chunk), derivation: 'extracted-from-mbox', notes: [] });
  }
  return {
    messages,
    truncated,
    notes: truncated ? [`The mailbox holds ${starts.length} messages; only the first ${maxMessages} were extracted (MAILSHARK_MAX_MBOX_MESSAGES).`] : [],
  };
}

/** mboxrd: a body line ">From " (with one or more ">") had one ">" added on write; remove it. */
function unescapeMboxrd(chunk: Uint8Array): Uint8Array {
  const out: number[] = [];
  let changed = false;
  let lineStart = true;
  for (let i = 0; i < chunk.length; i++) {
    const c = chunk[i] as number;
    if (lineStart && c === 0x3e) {
      let j = i;
      while (j < chunk.length && chunk[j] === 0x3e) j++;
      if (j + 5 <= chunk.length && chunk[j] === 0x46 && chunk[j + 1] === 0x72 && chunk[j + 2] === 0x6f && chunk[j + 3] === 0x6d && chunk[j + 4] === 0x20) {
        changed = true;
        lineStart = false;
        continue; // drop exactly one '>'
      }
    }
    out.push(c);
    lineStart = c === 0x0a;
  }
  return changed ? Uint8Array.from(out) : chunk;
}

// ── Outlook .msg → RFC 5322 reconstruction ──────────────────────────────────

const MIME_STRUCTURE_HEADERS = /^(content-type|content-transfer-encoding|mime-version|content-disposition|content-id)$/i;

function foldBase64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64').replace(/.{1,76}/g, (m) => m + '\r\n');
}

function encodeWord(s: string): string {
  // eslint-disable-next-line no-control-regex
  return /^[\x20-\x7e]*$/.test(s) ? s : `=?UTF-8?B?${Buffer.from(s, 'utf8').toString('base64')}?=`;
}

function rfc2822Date(iso: string | undefined): string | null {
  if (!iso) return null;
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? null : d.toUTCString().replace('GMT', '+0000');
}

const CODEPAGES: Record<number, string> = { 65001: 'utf-8', 1252: 'windows-1252', 28591: 'iso-8859-1', 1250: 'windows-1250', 1251: 'windows-1251', 932: 'shift_jis', 936: 'gbk', 949: 'euc-kr', 950: 'big5', 20127: 'us-ascii' };

export function msgToEml(bytes: Uint8Array): ExtractedMessage {
  let data: ReturnType<MsgReader['getFileData']>;
  let reader: MsgReader;
  try {
    const ab = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
    reader = new MsgReader(ab);
    data = reader.getFileData();
  } catch (e) {
    throw new FormatError('msg-parse-error', `The Outlook file could not be parsed: ${e instanceof Error ? e.message : String(e)}`);
  }
  if ((data as { error?: string }).error) throw new FormatError('msg-parse-error', `The Outlook file could not be parsed: ${(data as { error?: string }).error}`);

  // Boundaries derive from the input hash so the same .msg always reconstructs to the same bytes.
  const seed = createHash('sha256').update(bytes).digest('hex').slice(0, 20);
  const notes = ['Reconstructed from an Outlook .msg item: the MIME structure is synthetic, so byte-level checks (DKIM body hash, MIME anomalies) do not apply.'];
  const headerLines: string[] = [];
  const transport = (data.headers ?? '').replace(/\r?\n/g, '\r\n').trim();
  if (transport) {
    // Keep every original transport header except those describing the original MIME tree.
    let skip = false;
    for (const line of transport.split('\r\n')) {
      if (/^[ \t]/.test(line)) {
        if (!skip) headerLines.push(line);
        continue;
      }
      const name = line.slice(0, Math.max(0, line.indexOf(':'))).trim();
      skip = MIME_STRUCTURE_HEADERS.test(name);
      if (!skip) headerLines.push(line);
    }
    notes.push('Transport headers were present in the .msg file and are preserved.');
  } else {
    const from = data.senderSmtpAddress || data.senderEmail || '';
    headerLines.push(`From: ${encodeWord(data.senderName || '')} <${from}>`);
    const rcpt = (kind: string): string =>
      (data.recipients ?? [])
        .filter((r) => (r.recipType ?? 'to') === kind)
        .map((r) => `${encodeWord(r.name || '')} <${r.smtpAddress || r.email || ''}>`)
        .join(', ');
    if (rcpt('to')) headerLines.push(`To: ${rcpt('to')}`);
    if (rcpt('cc')) headerLines.push(`Cc: ${rcpt('cc')}`);
    if (data.subject) headerLines.push(`Subject: ${encodeWord(data.subject)}`);
    const date = rfc2822Date(data.clientSubmitTime ?? data.messageDeliveryTime);
    if (date) headerLines.push(`Date: ${date}`);
    if (data.messageId) headerLines.push(`Message-ID: ${data.messageId}`);
    notes.push('No transport headers were stored in the .msg file (typical of drafts or items saved before sending): the delivery path and authentication results are unavailable.');
  }
  headerLines.push('X-MailShark-Derivation: reconstructed-from-msg');
  headerLines.push('MIME-Version: 1.0');

  let html = data.bodyHtml ?? null;
  if (!html && data.html && data.html.length) {
    const enc = CODEPAGES[data.internetCodepage ?? 65001] ?? 'utf-8';
    try {
      html = new TextDecoder(enc).decode(data.html);
    } catch {
      html = new TextDecoder('utf-8').decode(data.html);
    }
  }
  const text = data.body ?? null;
  const alt: string[] = [];
  if (text) alt.push(`Content-Type: text/plain; charset="utf-8"\r\nContent-Transfer-Encoding: base64\r\n\r\n${foldBase64(new TextEncoder().encode(text))}`);
  if (html) alt.push(`Content-Type: text/html; charset="utf-8"\r\nContent-Transfer-Encoding: base64\r\n\r\n${foldBase64(new TextEncoder().encode(html))}`);
  if (!alt.length) alt.push('Content-Type: text/plain; charset="utf-8"\r\n\r\n');

  const parts: string[] = [];
  const bAlt = `=_ms_alt_${seed}`;
  parts.push(alt.length > 1 ? `Content-Type: multipart/alternative; boundary="${bAlt}"\r\n\r\n${alt.map((p) => `--${bAlt}\r\n${p}\r\n`).join('')}--${bAlt}--` : (alt[0] as string));
  for (const att of data.attachments ?? []) {
    if ((att as { innerMsgContent?: true }).innerMsgContent) {
      notes.push(`Embedded Outlook item "${att.fileName ?? att.name ?? 'message'}" was not expanded.`);
      continue;
    }
    try {
      const a = reader.getAttachment(att);
      const name = (a.fileName || 'attachment').replace(/[\r\n"]/g, '_');
      const mime = (att as { attachMimeTag?: string }).attachMimeTag || 'application/octet-stream';
      parts.push(
        `Content-Type: ${mime}; name="${encodeWord(name)}"\r\nContent-Disposition: attachment; filename*=UTF-8''${encodeURIComponent(name)}\r\nContent-Transfer-Encoding: base64\r\n\r\n${foldBase64(a.content)}`,
      );
    } catch {
      notes.push(`Attachment "${att.fileName ?? 'unnamed'}" could not be read from the .msg file.`);
    }
  }
  let body: string;
  if (parts.length === 1) {
    headerLines.push(...(parts[0] as string).split('\r\n\r\n', 1)[0]!.split('\r\n'));
    body = (parts[0] as string).slice((parts[0] as string).indexOf('\r\n\r\n') + 4);
  } else {
    const bMix = `=_ms_mix_${seed}`;
    headerLines.push(`Content-Type: multipart/mixed; boundary="${bMix}"`);
    body = parts.map((p) => `--${bMix}\r\n${p}\r\n`).join('') + `--${bMix}--\r\n`;
  }
  const eml = headerLines.join('\r\n') + '\r\n\r\n' + body;
  return { index: 0, offset: null, bytes: new TextEncoder().encode(eml), derivation: 'reconstructed-from-msg', notes };
}
