// Received-chain forensics: reconstructs the delivery path and separates hops written by the
// recipient's own servers (trustworthy) from hops the sender could have forged.
import type { Hop, RouteAnalysis } from '../types';
import { hostInfo, isIpLiteral, isPublicIp, orgDomain } from '../util/domain';
import { collapseWs } from '../util/text';

const IP_BRACKET_RE = /\[(?:IPv6:)?([0-9a-fA-F:.]+)\]/g;
const IPV4_RE = /\b((?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3})\b/;

export function parseDate(s: string | null | undefined): number | null {
  if (!s) return null;
  const cleaned = s
    .replace(/\([^)]*\)/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
  let t = Date.parse(cleaned);
  if (Number.isNaN(t)) {
    // Tolerate "Mon, 21 Sep 2026 08:49:05 -0700 PDT" style trailing zone names.
    t = Date.parse(cleaned.replace(/\s+[A-Z]{2,5}$/, ''));
  }
  return Number.isNaN(t) ? null : t;
}

export function parseReceived(raw: string, index: number): Hop {
  const value = collapseWs(raw);
  const semi = value.lastIndexOf(';');
  const main = semi >= 0 ? value.slice(0, semi) : value;
  const datePart = semi >= 0 ? value.slice(semi + 1) : null;

  const fromIdx = main.search(/\bfrom\s/i);
  const byIdx = main.search(/\bby\s/i);
  const fromClause = fromIdx >= 0 ? main.slice(fromIdx, byIdx > fromIdx ? byIdx : undefined) : '';
  const rest = byIdx >= 0 ? main.slice(byIdx) : main;

  const fromHost = /\bfrom\s+([^\s;()]+)/i.exec(fromClause)?.[1] ?? null;
  const paren = /\(([^)]*)\)/.exec(fromClause)?.[1] ?? '';
  let fromIp: string | null = null;
  const brackets = [...fromClause.matchAll(IP_BRACKET_RE)].map((m) => m[1] as string).filter(isIpLiteral);
  if (brackets.length) fromIp = brackets[brackets.length - 1] as string;
  if (!fromIp) {
    const bare = IPV4_RE.exec(paren);
    if (bare) fromIp = bare[1] as string;
    else if (fromHost && isIpLiteral(fromHost.replace(/^\[|\]$/g, ''))) fromIp = fromHost.replace(/^\[|\]$/g, '');
  }
  let fromRdns: string | null = null;
  const rdnsMatch = /^\s*([a-z0-9][a-z0-9.-]*\.[a-z]{2,})\.?\s/i.exec(paren + ' ');
  if (rdnsMatch && rdnsMatch[1] && !isIpLiteral(rdnsMatch[1])) fromRdns = rdnsMatch[1].toLowerCase();

  const byHost = /\bby\s+([^\s;()]+)/i.exec(rest)?.[1] ?? null;
  const protocol = /\bwith\s+([A-Za-z][A-Za-z0-9_-]*(?:\s+SMTP\s+Server)?)/i.exec(rest)?.[1] ?? null;
  const tlsMatch = /\b(TLSv?1[._]\d|TLS1_\d|version=TLS[\w_.]+|TLS_[A-Z0-9_]+)/i.exec(value);
  const tls = tlsMatch ? tlsMatch[1]!.replace(/^version=/i, '') : protocol && /ESMTPS|ESMTPSA|TLS/i.test(protocol) ? 'TLS' : null;

  return {
    index,
    raw: value,
    fromHost: fromHost ? fromHost.toLowerCase() : null,
    fromRdns,
    fromIp,
    fromIpPublic: fromIp ? isPublicIp(fromIp) : false,
    byHost: byHost ? byHost.toLowerCase().replace(/\.$/, '') : null,
    protocol,
    tls,
    timestamp: parseDate(datePart),
    delaySec: null,
    trusted: false,
  };
}

const PROVIDER_ORGS = new Set([
  'google.com', 'outlook.com', 'hotmail.com', 'office365.com', 'microsoft.com', 'yahoo.com', 'yahoodns.net', 'aol.com',
  'icloud.com', 'apple.com', 'me.com', 'protonmail.ch', 'proton.me', 'zoho.com', 'zohomail.com', 'fastmail.com',
  'messagingengine.com', 'gmx.net', 'web.de', 'mail.ru', 'yandex.net', 'yandex.ru', 'mimecast.com', 'pphosted.com',
]);

export function analyzeRoute(receivedHeaders: string[], dateHeader: string | null): RouteAnalysis {
  const newestFirst = receivedHeaders.map((r, i) => parseReceived(r, i));

  // The receiving organisation is the first named "by" host from the top.
  let receiverOrg: string | null = null;
  for (const hop of newestFirst) {
    if (hop.byHost && !isIpLiteral(hop.byHost) && hop.byHost.includes('.')) {
      receiverOrg = orgDomain(hop.byHost);
      break;
    }
  }
  const receiverOrgs = new Set<string>();
  if (receiverOrg) {
    receiverOrgs.add(receiverOrg);
    if (receiverOrg === 'outlook.com' || receiverOrg === 'office365.com') ['outlook.com', 'office365.com', 'microsoft.com'].forEach((o) => receiverOrgs.add(o));
  }

  const internal = (host: string | null): boolean => {
    if (!host) return false;
    const h = host.replace(/^\[|\]$/g, '');
    if (isIpLiteral(h)) return !isPublicIp(h);
    return receiverOrgs.has(orgDomain(h));
  };

  // Walk top-down: hops stay trusted while they were written by the receiver's infrastructure.
  // The first hop whose sender is outside that infrastructure is the hand-off: its from-IP is
  // the true connecting client. Everything older was reported by the sender and is unverified.
  let originIp: string | null = null;
  let originHost: string | null = null;
  let chainIntact = true;
  for (const hop of newestFirst) {
    // Hops above the hand-off can only have been written by the receiver, and receivers often
    // label internal relays with bare IPs (e.g. Gmail's "by 2002:a05:…"), so IP-literal "by" counts.
    const byHost = hop.byHost?.replace(/^\[|\]$/g, '') ?? null;
    const byInternal =
      !byHost || isIpLiteral(byHost) || internal(byHost) || (receiverOrg !== null && PROVIDER_ORGS.has(orgDomain(byHost)));
    if (!chainIntact || !byInternal) {
      chainIntact = false;
      continue;
    }
    hop.trusted = true;
    const fromInternal = (hop.fromIp && !hop.fromIpPublic) || internal(hop.fromRdns) || internal(hop.fromHost);
    if (hop.fromIp && hop.fromIpPublic && !fromInternal) {
      originIp = hop.fromIp;
      originHost = hop.fromRdns ?? (hop.fromHost && !isIpLiteral(hop.fromHost) ? hop.fromHost : null);
      chainIntact = false;
    }
  }
  // Fallback when the chain gives no clear hand-off (e.g. corpora without receiver headers).
  if (!originIp) {
    for (let i = newestFirst.length - 1; i >= 0; i--) {
      const hop = newestFirst[i] as Hop;
      if (hop.fromIp && hop.fromIpPublic) {
        originIp = hop.fromIp;
        originHost = hop.fromRdns ?? (hop.fromHost && !isIpLiteral(hop.fromHost) ? hop.fromHost : null);
        break;
      }
    }
  }

  const hops = [...newestFirst].reverse();
  for (let i = 1; i < hops.length; i++) {
    const a = hops[i - 1] as Hop;
    const b = hops[i] as Hop;
    if (a.timestamp !== null && b.timestamp !== null) b.delaySec = Math.round((b.timestamp - a.timestamp) / 1000);
  }
  const stamps = hops.map((h) => h.timestamp).filter((t): t is number => t !== null);
  const totalTransitSec = stamps.length >= 2 ? Math.round((Math.max(...stamps) - Math.min(...stamps)) / 1000) : null;
  const dateTs = parseDate(dateHeader);
  const firstTrusted = newestFirst.filter((h) => h.trusted && h.timestamp !== null).pop();
  const dateSkewSec = dateTs !== null && firstTrusted?.timestamp != null ? Math.round((firstTrusted.timestamp - dateTs) / 1000) : null;

  const originOrg = originHost ? orgDomain(originHost) : null;
  return {
    hops,
    receiverOrg,
    originIp,
    originHost: originHost ? hostInfo(originHost).host : null,
    originOrg: originOrg || null,
    totalTransitSec,
    dateHeader: dateTs,
    dateSkewSec,
  };
}
