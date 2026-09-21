// MailShark engine entry point: raw RFC 5322 bytes → forensic Report.
import PostalMime from 'postal-mime';
import { REPORT_SCHEMA, type AnalyzeOptions, type AttachmentAnalysis, type Report, type StructureAnalysis } from './types';
import { firstHeader, headerValues, parseHeaderBlock, splitMessage, toHeaderEntries, walkMime, decodeHeaderValue } from './mime/raw';
import { analyzeRoute, parseDate } from './analyzers/route';
import { analyzeAuth } from './analyzers/auth';
import { analyzeSender, parseAddressList } from './analyzers/sender';
import { analyzeHtml } from './analyzers/html';
import { analyzeLinks, extractTextUrls, type LinkCandidate } from './analyzers/links';
import { analyzeContent } from './analyzers/content';
import { analyzeAttachment, type RawAttachment } from './analyzers/attachments';
import { detectEsp } from './analyzers/esp';
import { buildFindings, scoreFindings, sortFindings } from './score';
import { buildFingerprint } from './fingerprint';
import { md5Hex, sha1Hex, sha256Hex } from './util/hash';
import { jaccard, latin1, latin1ToBytes, tokenize } from './util/text';

export const ENGINE_VERSION = '1.0.0';

const SINGLE_INSTANCE = ['from', 'sender', 'reply-to', 'to', 'cc', 'subject', 'date', 'message-id', 'in-reply-to', 'references', 'content-type', 'mime-version'];

function toBytes(content: ArrayBuffer | Uint8Array | string): Uint8Array {
  if (content instanceof Uint8Array) return content;
  if (content instanceof ArrayBuffer) return new Uint8Array(content);
  return new TextEncoder().encode(content);
}

function base64ToBytes(b64: string): Uint8Array | null {
  try {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  } catch {
    return null;
  }
}

async function mapLimit<T, R>(items: T[], limit: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const out: R[] = new Array(items.length);
  let next = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (next < items.length) {
      const i = next++;
      out[i] = await fn(items[i] as T);
    }
  });
  await Promise.all(workers);
  return out;
}

export async function analyzeEmail(input: Uint8Array | ArrayBuffer | string, options: AnalyzeOptions = {}): Promise<Report> {
  const t0 = performance.now();
  const timings: Record<string, number> = {};
  const mark = (name: string, start: number): void => {
    timings[name] = Math.round((performance.now() - start) * 10) / 10;
  };
  // Strings are normally binary (Latin-1, one char per byte). Text pasted by a user may contain real
  // Unicode characters instead; those are encoded as UTF-8 so nothing is silently truncated.
  // eslint-disable-next-line no-control-regex
  const raw = typeof input === 'string' ? (/[^\x00-\xff]/.test(input) ? new TextEncoder().encode(input) : latin1ToBytes(input)) : toBytes(input);
  const rawStr = latin1(raw);

  let t = performance.now();
  const [sha256, sha1] = await Promise.all([sha256Hex(raw), sha1Hex(raw)]);
  const md5 = md5Hex(raw);
  mark('hash', t);

  // ── Headers & MIME ──
  t = performance.now();
  const { headerBlock } = splitMessage(rawStr);
  const { headers, malformed } = parseHeaderBlock(headerBlock);
  const email = await PostalMime.parse(raw, { attachmentEncoding: 'arraybuffer', rfc822Attachments: true });
  const mime = walkMime(rawStr);
  mark('parse', t);

  const hv = (k: string): string | null => firstHeader(headers, k);
  const subject = decodeHeaderValue(hv('subject') ?? '');
  const xMailer = hv('x-mailer') ?? hv('user-agent') ?? hv('x-sender-software');

  // ── Route & authentication ──
  t = performance.now();
  const route = analyzeRoute(headerValues(headers, 'received'), hv('date'));
  const fromList = parseAddressList(hv('from'));
  const fromDomain = fromList[0]?.domain ?? null;
  const auth = analyzeAuth({
    authResults: headerValues(headers, 'authentication-results'),
    arcAuthResults: headerValues(headers, 'arc-authentication-results'),
    receivedSpf: headerValues(headers, 'received-spf'),
    dkimSignatures: headerValues(headers, 'dkim-signature'),
    receiverOrg: route.receiverOrg,
    fromDomain,
  });
  const sender = analyzeSender({
    fromRaw: hv('from'),
    replyToRaw: hv('reply-to'),
    returnPathRaw: hv('return-path'),
    senderRaw: hv('sender'),
    auth,
    subject,
    senderSeenCount: options.context?.senderSeenCount,
  });
  mark('identity', t);

  // ── Body ──
  t = performance.now();
  const htmlRes = analyzeHtml(email.html);
  const plain = email.text ?? '';
  const bodyText = htmlRes.visibleText || plain;
  mark('html', t);

  // ── Attachments (+ inline data-URI images for QR codes) ──
  t = performance.now();
  const maxInspect = options.maxInspectBytes ?? 15_000_000;
  const rawAtts: RawAttachment[] = email.attachments.map((a) => ({
    filename: a.filename,
    mimeType: a.mimeType,
    disposition: a.disposition,
    contentId: a.contentId,
    content: toBytes(a.content),
  }));
  for (const [i, img] of htmlRes.dataImages.entries()) {
    const bytes = base64ToBytes(img.base64);
    if (bytes && bytes.length > 200) rawAtts.push({ filename: `embedded-image-${i + 1}.${img.mime.split('/')[1] ?? 'img'}`, mimeType: img.mime, disposition: 'inline', contentId: `data-${i}`, content: bytes });
  }
  const attachments: AttachmentAnalysis[] = await mapLimit(rawAtts.slice(0, 40), 3, (a) => analyzeAttachment(a, options.qrDecoder, maxInspect));
  mark('attachments', t);

  // ── Links ──
  t = performance.now();
  const candidates: LinkCandidate[] = [...htmlRes.links];
  for (const u of extractTextUrls(plain.slice(0, 200_000))) candidates.push({ url: u, source: 'text' });
  if (!email.html) for (const u of extractTextUrls(bodyText.slice(0, 200_000))) candidates.push({ url: u, source: 'text' });
  for (const a of attachments) {
    for (const u of a.urls) candidates.push({ url: u, source: a.qr === u ? 'qr' : 'attachment' });
  }
  const unsubscribe = new Set<string>();
  const lu = hv('list-unsubscribe');
  if (lu) for (const m of lu.matchAll(/<(https?:[^>]+)>/gi)) unsubscribe.add(m[1] as string);
  for (const u of unsubscribe) candidates.push({ url: u, source: 'header' });
  const links = analyzeLinks(candidates, options.intel, unsubscribe).slice(0, 250);
  mark('links', t);

  // ── Content ──
  t = performance.now();
  const content = analyzeContent({
    subject,
    text: bodyText,
    inReplyTo: hv('in-reply-to'),
    references: hv('references'),
    hasLinks: links.some((l) => l.sources.includes('html-anchor') || l.sources.includes('text')),
    hasAttachments: attachments.some((a) => !a.inline),
  });
  mark('content', t);

  // ── Structure ──
  const counts = new Map<string, number>();
  for (const h of headers) counts.set(h.key, (counts.get(h.key) ?? 0) + 1);
  const duplicateHeaders = SINGLE_INSTANCE.filter((k) => (counts.get(k) ?? 0) > 1);
  let divergence: number | null = null;
  if (plain && htmlRes.visibleText) {
    const tt = tokenize(plain);
    const ht = tokenize(htmlRes.visibleText);
    if (tt.length >= 30 && ht.length >= 30) divergence = Math.round((1 - (jaccard(tt, ht) ?? 1)) * 100) / 100;
  }
  const anomalies = [...mime.anomalies];
  if (malformed > 2) anomalies.push('malformed-header-lines');
  if (!headers.some((h) => h.key === 'message-id')) anomalies.push('missing-message-id');
  if (!headers.some((h) => h.key === 'date')) anomalies.push('missing-date');
  const structure: StructureAnalysis = {
    parts: mime.parts.slice(0, 120),
    partCount: mime.parts.length,
    maxDepth: mime.parts.reduce((m, p) => Math.max(m, p.depth), 0),
    hasText: !!plain,
    hasHtml: !!email.html,
    textHtmlDivergence: divergence,
    duplicateHeaders,
    anomalies,
  };

  // ── Bulk sender ──
  const hostHints = [
    route.originHost ?? '',
    sender.returnPath?.domain ?? '',
    ...auth.signatures.map((s) => s.domain),
    ...route.hops.flatMap((h) => [h.fromRdns ?? '', h.fromHost ?? '']),
  ].filter(Boolean);
  const envelopeFrom = hv('return-path') ?? auth.results.find((r) => r.method === 'spf')?.props['smtp.mailfrom'] ?? '';
  const esp = detectEsp(headers, hostHints, envelopeFrom);

  // ── Verdict ──
  t = performance.now();
  const findings = sortFindings(
    buildFindings({
      sender,
      auth,
      route,
      links,
      html: htmlRes.analysis,
      hiddenTextSample: htmlRes.hiddenText.slice(0, 200),
      content,
      attachments,
      structure,
      esp,
      xMailer,
      hasListUnsubscribe: !!lu,
      intel: options.intel,
      senderSeenCount: options.context?.senderSeenCount,
    }),
  );
  const scored = scoreFindings(findings, auth.source, bodyText.length);
  mark('score', t);

  const dateTs = parseDate(hv('date'));
  const time = route.hops.length ? (route.hops[route.hops.length - 1]?.timestamp ?? dateTs) : dateTs;
  const fingerprint = buildFingerprint({
    time: time ?? (options.now ?? new Date()).getTime(),
    headers,
    messageId: hv('message-id'),
    xMailer,
    sender,
    auth,
    route,
    content,
    html: htmlRes.analysis,
    bodyText,
    links,
    attachments,
    esp,
  });

  const { claimed: _claimed, ...senderPublic } = sender;
  void _claimed;
  timings['total'] = Math.round((performance.now() - t0) * 10) / 10;
  return {
    schema: REPORT_SCHEMA,
    engineVersion: ENGINE_VERSION,
    id: sha256,
    analyzedAt: (options.now ?? new Date()).toISOString(),
    sizeBytes: raw.length,
    hashes: { sha256, sha1, md5 },
    summary: {
      subject,
      from: sender.from,
      to: parseAddressList(hv('to')).slice(0, 20),
      date: dateTs !== null ? new Date(dateTs).toISOString() : null,
      messageId: hv('message-id'),
    },
    ...scored,
    findings,
    sender: senderPublic,
    auth,
    route,
    links,
    html: htmlRes.analysis,
    content,
    attachments,
    structure,
    esp,
    headers: toHeaderEntries(headers).slice(0, 400),
    fingerprint,
    timings,
  };
}

