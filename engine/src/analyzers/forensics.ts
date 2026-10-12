// Header forensics beyond the delivery path: who really submitted the message (provider-side
// trace headers), whether authentication verdicts were injected by the sender, whether the
// connecting server lied about its name, and whether the recorded timeline is consistent.
import type { HeaderForensics, OriginatingInfo, RouteAnalysis } from '../types';
import type { RawHeader } from '../mime/raw';
import { parseAuthResults } from './auth';
import { isBrandDomain, BRANDS } from '../data/brands';
import { isIpLiteral, isPublicIp, orgDomain } from '../util/domain';
import { collapseWs } from '../util/text';

// Large mailbox providers that write Authentication-Results under their own authserv-id. If a
// message carries such a header but never passed through that provider, the header is forged.
const PROVIDER_AUTHSERV: Record<string, string[]> = {
  google: ['google.com', 'googlemail.com', 'gmail.com'],
  microsoft: ['outlook.com', 'office365.com', 'microsoft.com', 'hotmail.com', 'outlook.office365.com'],
  yahoo: ['yahoo.com', 'yahoodns.net', 'aol.com'],
  apple: ['icloud.com', 'apple.com', 'me.com'],
  zoho: ['zoho.com', 'zohomail.com'],
  proton: ['protonmail.ch', 'proton.me'],
  yandex: ['yandex.net', 'yandex.ru'],
  mailru: ['mail.ru'],
  gmx: ['gmx.net', 'web.de'],
};

function providerOf(org: string): string | null {
  for (const [p, orgs] of Object.entries(PROVIDER_AUTHSERV)) if (orgs.includes(org)) return p;
  return null;
}

const IP_IN_TEXT = /\b(?:\d{1,3}\.){3}\d{1,3}\b|\b[0-9a-f]{1,4}(?::[0-9a-f]{0,4}){2,7}\b/i;

function firstIp(value: string): string | null {
  const m = IP_IN_TEXT.exec(value.replace(/[[\]]/g, ' '));
  if (!m) return null;
  const ip = m[0];
  return isIpLiteral(ip) ? ip : null;
}

// Provider-side trace headers. They are written by the sending provider's MTA or webmail (not by
// the recipient), so they cannot be verified from the evidence alone, but forgers rarely add them.
const CLIENT_IP_HEADERS = ['x-originating-ip', 'x-sender-ip', 'x-source-ip', 'x-client-ip', 'x-yahoo-post-ip', 'x-forwarded-for', 'x-real-ip'];

export function extractOriginating(headers: RawHeader[]): OriginatingInfo {
  const get = (k: string): string | null => headers.find((h) => h.key === k)?.value ?? null;
  const all = (k: string): string[] => headers.filter((h) => h.key === k).map((h) => h.value);

  let clientIp: string | null = null;
  let clientIpHeader: string | null = null;
  for (const k of CLIENT_IP_HEADERS) {
    const v = get(k);
    const ip = v ? firstIp(v) : null;
    if (ip && isPublicIp(ip)) {
      clientIp = ip;
      clientIpHeader = headers.find((h) => h.key === k)?.name ?? k;
      break;
    }
  }

  // cPanel / Exim: authenticated account that submitted the message.
  let authenticatedSender: string | null = null;
  const via = get('x-get-message-sender-via');
  const viaId = via ? /authenticated_id:\s*([^\s;]+)/i.exec(via)?.[1] : null;
  const authHdr = get('x-authenticated-sender');
  const authAddr = authHdr ? /([\w.+-]+@[\w.-]+\.[a-z]{2,})/i.exec(authHdr)?.[1] : null;
  authenticatedSender = (authAddr ?? viaId ?? null)?.toLowerCase() ?? null;

  // A web script that called mail(): the strongest pointer to a compromised website.
  let sendingScript: string | null = null;
  let scriptHeader: string | null = null;
  for (const k of ['x-php-script', 'x-php-originating-script', 'x-source-args', 'x-source']) {
    const v = get(k);
    if (v && /\.php|\/home\/|public_html|\/var\/www|cgi-bin|\.pl\b|\.py\b/i.test(v)) {
      sendingScript = collapseWs(v).slice(0, 300);
      scriptHeader = headers.find((h) => h.key === k)?.name ?? k;
      if (!clientIp && k === 'x-php-script') {
        const ip = /\bfor\s+([0-9a-f:.]+)/i.exec(v)?.[1];
        if (ip && isIpLiteral(ip) && isPublicIp(ip)) {
          clientIp = ip;
          clientIpHeader = scriptHeader;
        }
      }
      break;
    }
  }

  let hostingServer: string | null = null;
  for (const v of all('x-antiabuse')) {
    const m = /primary hostname\s*-\s*(\S+)/i.exec(v);
    if (m) hostingServer = (m[1] as string).toLowerCase();
  }
  if (!hostingServer && via) hostingServer = /^\s*([a-z0-9.-]+\.[a-z]{2,})\s*:/i.exec(via)?.[1]?.toLowerCase() ?? null;
  const sourceDir = get('x-source-dir');

  return {
    clientIp,
    clientIpHeader,
    authenticatedSender,
    sendingScript,
    scriptHeader,
    hostingServer,
    sourceDir: sourceDir ? collapseWs(sourceDir).slice(0, 200) : null,
  };
}

export interface ForensicsInputs {
  headers: RawHeader[];
  route: RouteAnalysis;
  trustedAuthServId: string | null;
  authSource: 'trusted' | 'topmost' | 'none';
  fromDomain: string | null;
}

export function analyzeHeaderForensics(x: ForensicsInputs): HeaderForensics {
  const originating = extractOriginating(x.headers);

  // ── Injected Authentication-Results ──
  const routeOrgs = new Set<string>();
  for (const hop of x.route.hops) {
    for (const h of [hop.byHost, hop.fromHost, hop.fromRdns]) {
      if (h && !isIpLiteral(h.replace(/^\[|\]$/g, ''))) routeOrgs.add(orgDomain(h));
    }
  }
  const routeProviders = new Set([...routeOrgs].map(providerOf).filter((p): p is string => !!p));
  const injected: HeaderForensics['injectedAuthResults'] = [];
  const arHeaders = x.headers.filter((h) => h.key === 'authentication-results');
  const parsed = arHeaders.map((h) => ({ raw: h.value, ...parseAuthResults(h.value) }));
  const trustedOrg = x.trustedAuthServId ? orgDomain(x.trustedAuthServId) : null;
  const verdict = (p: (typeof parsed)[number], m: string): string => p.results.filter((r) => r.method === m).map((r) => r.result).join(',') || '-';
  let seenTrusted = false;
  for (const p of parsed) {
    const org = p.authServId ? orgDomain(p.authServId) : '';
    if (x.authSource === 'trusted' && trustedOrg && org === trustedOrg) {
      if (!seenTrusted) {
        seenTrusted = true;
        continue;
      }
      // A second header under the receiver's own name, further down: it was already in the
      // message when the receiver got it. Conflicting verdicts make the forgery explicit.
      const first = parsed.find((q) => q.authServId && orgDomain(q.authServId) === trustedOrg) as (typeof parsed)[number];
      const conflict = ['dmarc', 'dkim', 'spf'].some((m) => verdict(first, m) !== verdict(p, m) && verdict(p, m) !== '-');
      if (conflict) injected.push({ authServId: p.authServId, reason: `Duplicates the receiving server's verdict header with different results (receiver: ${['spf', 'dkim', 'dmarc'].map((m) => `${m}=${verdict(first, m)}`).join(' ')}; injected: ${['spf', 'dkim', 'dmarc'].map((m) => `${m}=${verdict(p, m)}`).join(' ')}).`, value: collapseWs(p.raw).slice(0, 300) });
      continue;
    }
    const provider = org ? providerOf(org) : null;
    if (provider && !routeProviders.has(provider) && x.route.hops.length > 0) {
      injected.push({ authServId: p.authServId, reason: `Claims to be the verdict of ${org}, but no server of that provider appears anywhere in the delivery path.`, value: collapseWs(p.raw).slice(0, 300) });
    }
  }

  // ── HELO / reverse-DNS contradiction at the hand-off ──
  let heloMismatch: HeaderForensics['heloMismatch'] = null;
  const handoff = x.route.hops.find((h) => h.trusted && h.fromIp && h.fromIp === x.route.originIp) ?? null;
  if (handoff && handoff.fromHost && !isIpLiteral(handoff.fromHost.replace(/^\[|\]$/g, '')) && handoff.fromHost.includes('.')) {
    const heloOrg = orgDomain(handoff.fromHost);
    const claimsBrand = BRANDS.some((b) => isBrandDomain(b, heloOrg)) || providerOf(heloOrg) !== null;
    const rdnsOrg = handoff.fromRdns ? orgDomain(handoff.fromRdns) : null;
    if (claimsBrand && rdnsOrg !== heloOrg) {
      heloMismatch = { helo: handoff.fromHost, rdns: handoff.fromRdns, ip: handoff.fromIp as string, verified: rdnsOrg !== null };
    }
  }

  // ── Timeline consistency (hops are oldest → newest) ──
  const anomalies: HeaderForensics['timestampAnomalies'] = [];
  const hops = x.route.hops;
  for (let i = 1; i < hops.length; i++) {
    const prev = hops[i - 1];
    const cur = hops[i];
    if (!prev || !cur || prev.timestamp === null || cur.timestamp === null) continue;
    const delta = Math.round((cur.timestamp - prev.timestamp) / 1000);
    if (delta < -7200) anomalies.push({ fromHop: prev.index, toHop: cur.index, deltaSec: delta, involvesUnverifiedHop: !prev.trusted || !cur.trusted });
  }

  const mid = x.headers.find((h) => h.key === 'message-id')?.value ?? '';
  const midDomain = /@([^<>\s]+)>?\s*$/.exec(mid)?.[1]?.toLowerCase() ?? null;

  return {
    originating,
    injectedAuthResults: injected,
    heloMismatch,
    timestampAnomalies: anomalies,
    messageIdDomain: midDomain,
    messageIdMatchesFrom: midDomain && x.fromDomain ? orgDomain(midDomain) === orgDomain(x.fromDomain) : null,
  };
}
