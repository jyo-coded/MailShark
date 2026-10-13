// Indicator-of-compromise extraction. Every indicator records its role in the message and the
// component it came from, so a report can say *where* a value was observed, not only that it was.
// Values are normalised (lowercase addresses/hosts, E.164-like phones) but never "enriched": this
// module states what the evidence contains, nothing more.
import type {
  AttachmentAnalysis,
  ContentAnalysis,
  DkimVerification,
  EspInfo,
  HeaderForensics,
  Ioc,
  IocRole,
  IocType,
  LinkAnalysis,
  RouteAnalysis,
  SenderAnalysis,
} from './types';
import { hostInfo, isIPv4, isIPv6, isPublicIp } from './util/domain';

export interface IocInputs {
  sender: SenderAnalysis;
  recipient: string | null;
  route: RouteAnalysis;
  /** Raw header positions of Received headers (top-most = 0) are their hop indexes. */
  links: LinkAnalysis[];
  attachments: AttachmentAnalysis[];
  content: ContentAnalysis;
  dkim: DkimVerification[];
  forensics: HeaderForensics | null;
  messageId: string | null;
  esp: EspInfo | null;
}

export function normalizePhone(p: string): string {
  const plus = p.trim().startsWith('+');
  const digits = p.replace(/\D/g, '');
  return (plus ? '+' : '') + digits;
}

const BTC_BECH32 = /^bc1[ac-hj-np-z02-9]{25,62}$/;
const BTC_BASE58 = /^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$/;
const ETH = /^0x[a-fA-F0-9]{40}$/;
const XMR = /^4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}$/;

/** Cryptocurrency addresses in free text (deduplicated, capped). Token-based: linear and cheap. */
export function findWallets(text: string): { type: 'btc' | 'eth' | 'xmr'; value: string }[] {
  const out = new Map<string, { type: 'btc' | 'eth' | 'xmr'; value: string }>();
  for (const tok of text.slice(0, 100_000).split(/[^A-Za-z0-9]+/)) {
    const n = tok.length;
    if (n < 26 || n > 95) continue;
    if (n === 42 && ETH.test(tok)) out.set(tok.toLowerCase(), { type: 'eth', value: tok.toLowerCase() });
    else if (n === 95 && XMR.test(tok)) out.set(tok, { type: 'xmr', value: tok });
    else if (BTC_BECH32.test(tok)) out.set(tok, { type: 'btc', value: tok });
    // Legacy base58 addresses look like random tokens; require a digit and mixed case to avoid words.
    else if (n <= 35 && BTC_BASE58.test(tok) && /\d/.test(tok) && /[a-z]/.test(tok) && /[A-Z]/.test(tok)) out.set(tok, { type: 'btc', value: tok });
    if (out.size >= 20) break;
  }
  return [...out.values()];
}

export function extractIocs(x: IocInputs): Ioc[] {
  const out: Ioc[] = [];
  const seen = new Set<string>();
  const add = (type: IocType, value: string | null | undefined, role: IocRole, ref: string, context?: string, suspicious?: boolean): void => {
    if (!value) return;
    const v = value.trim();
    if (!v) return;
    const key = `${type}|${v}|${role}`;
    if (seen.has(key)) return;
    seen.add(key);
    const ioc: Ioc = { type, value: v, role, ref };
    if (context) ioc.context = context;
    if (suspicious) ioc.suspicious = true;
    out.push(ioc);
  };
  const addAddress = (addr: string | null | undefined, role: IocRole, ref: string): void => {
    if (!addr || !addr.includes('@')) return;
    const a = addr.toLowerCase();
    add('email', a, role, ref);
    const domain = a.slice(a.lastIndexOf('@') + 1);
    if (domain) add('domain', hostInfo(domain).regDomain ?? domain, role, ref);
  };
  const ipType = (ip: string): IocType | null => (isIPv4(ip) ? 'ipv4' : isIPv6(ip) ? 'ipv6' : null);

  // ── Identities ──
  const s = x.sender;
  addAddress(s.from?.address, 'from', 'header:From');
  s.replyTo.forEach((r, i) => addAddress(r.address, 'reply-to', `header:Reply-To[${i}]`));
  addAddress(s.returnPath?.address, 'return-path', 'header:Return-Path');
  addAddress(s.sender?.address, 'sender', 'header:Sender');
  addAddress(s.displayNameAddress, 'display-name-address', 'header:From');
  addAddress(x.recipient, 'recipient', 'header:Delivered-To');
  addAddress(x.forensics?.originating.authenticatedSender, 'authenticated-sender', 'header:X-Authenticated-Sender');

  // ── Infrastructure ──
  if (x.route.originIp) {
    const hop = x.route.hops.find((h) => h.fromIp === x.route.originIp && h.trusted) ?? x.route.hops.find((h) => h.fromIp === x.route.originIp);
    const t = ipType(x.route.originIp);
    if (t) add(t, x.route.originIp, 'origin-ip', `header:Received[${hop?.index ?? 0}]`, x.route.originHost ?? undefined);
    if (hop?.fromHost && !/^\[/.test(hop.fromHost) && hop.fromHost.includes('.')) add('hostname', hop.fromHost, 'helo', `header:Received[${hop.index}]`);
  }
  for (const hop of x.route.hops) {
    if (!hop.fromIp || hop.fromIp === x.route.originIp || !isPublicIp(hop.fromIp)) continue;
    const t = ipType(hop.fromIp);
    if (t) add(t, hop.fromIp, 'relay-ip', `header:Received[${hop.index}]`, hop.trusted ? 'recorded by receiver' : 'claimed by sender side');
  }
  const o = x.forensics?.originating;
  if (o?.clientIp) {
    const t = ipType(o.clientIp);
    if (t) add(t, o.clientIp, 'client-ip', `header:${o.clientIpHeader ?? 'X-Originating-IP'}`);
  }
  x.dkim.forEach((d, i) => {
    if (d.domain) add('domain', d.domain, 'dkim-domain', `header:DKIM-Signature[${i}]`, `s=${d.selector}`);
  });
  if (x.messageId) add('message-id', x.messageId.replace(/^<|>$/g, ''), 'message-id', 'header:Message-ID');
  if (x.esp?.campaignId) add('esp-campaign', `${x.esp.id}:${x.esp.customerId ?? ''}:${x.esp.campaignId}`, 'esp', 'header:*', x.esp.name);

  // ── Links ──
  x.links.forEach((l, i) => {
    if (!l.host) return;
    const role: IocRole = l.sources.includes('qr') ? 'qr-link' : l.sources.every((src) => src === 'attachment') ? 'attachment-link' : 'link';
    const ctx = l.flags.length ? l.flags.join(' ') : undefined;
    const susp = l.risk >= 2;
    add('url', l.url, role, `link[${i}]`, ctx, susp);
    if (l.isIp) {
      const t = ipType(l.host);
      if (t) add(t, l.host, 'link-host', `link[${i}]`, undefined, susp);
    } else {
      add('hostname', l.host, 'link-host', `link[${i}]`, undefined, susp);
      if (l.regDomain) add('domain', l.regDomain, 'link-domain', `link[${i}]`, undefined, susp);
    }
  });

  // ── Attachments ──
  x.attachments.forEach((a, i) => {
    const ctx = `${a.detectedType}${a.inline ? ', inline' : ''}${a.flags.length ? `; ${a.flags.join(' ')}` : ''}`;
    const susp = a.risk >= 2;
    add('sha256', a.sha256, 'attachment', `attachment[${i}]`, ctx, susp);
    add('sha1', a.sha1, 'attachment', `attachment[${i}]`, ctx, susp);
    add('md5', a.md5, 'attachment', `attachment[${i}]`, ctx, susp);
    add('filename', a.filename, 'attachment-name', `attachment[${i}]`, a.detectedType, susp);
    for (const e of a.entries.slice(0, 50)) add('filename', e.name, 'archive-entry', `attachment[${i}]`, e.encrypted ? 'encrypted entry' : undefined);
  });

  // ── Body ──
  for (const p of x.content.phoneNumbers) add('phone', normalizePhone(p), 'body', 'body:text', p);
  for (const w of x.content.wallets ?? []) {
    const type: IocType = w.startsWith('0x') ? 'eth' : w.startsWith('4') && w.length === 95 ? 'xmr' : 'btc';
    add(type, w, 'body', 'body:text');
  }
  return out;
}

/** Render a value safe to paste into documents and chat (no live links). */
export function defang(value: string): string {
  return value.replace(/^http/i, 'hxxp').replace(/\./g, '[.]').replace(/@/g, '[@]').replace(/:\/\//, '[://]');
}
