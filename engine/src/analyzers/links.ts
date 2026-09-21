// URL forensics: extraction from text, unwrapping of security/redirect wrappers, lexical risk
// flags, and templating (so per-recipient tracking tokens don't hide campaign reuse).
import type { IntelProvider, LinkAnalysis, LinkSource } from '../types';
import {
  ESP_TRACKING_DOMAINS,
  FORM_SERVICES,
  FREE_HOSTING_SUFFIXES,
  SUSPICIOUS_TLDS,
  URL_SHORTENERS,
  hostInfo,
  hostMatchesSuffix,
  isPublicIp,
  toUnicodeHost,
} from '../util/domain';
import { hasMixedScriptWord, stringEntropy } from '../util/text';
import { detectLookalike } from './lookalike';

export interface LinkCandidate {
  url: string;
  source: LinkSource;
  text?: string | null;
}

const TEXT_URL_RE = /\b(?:https?:\/\/|www\.)[^\s<>"'`{}|\\^[\]]+/gi;
const TRAILING_PUNCT_RE = /[.,;:!?)\]}'"’”>]+$/;

export function extractTextUrls(text: string): string[] {
  const out: string[] = [];
  for (const m of text.matchAll(TEXT_URL_RE)) {
    let u = (m[0] as string).replace(TRAILING_PUNCT_RE, '');
    if (/^www\./i.test(u)) u = 'http://' + u;
    out.push(u);
  }
  return out;
}

function safeUrl(u: string): URL | null {
  try {
    return new URL(u.trim());
  } catch {
    return null;
  }
}

/** Unwrap Google/Outlook SafeLinks/Proofpoint/Facebook/LinkedIn redirect wrappers. */
export function unwrapUrl(raw: string): { url: string; wrapper: string | null } {
  let current = raw;
  let wrapper: string | null = null;
  for (let depth = 0; depth < 4; depth++) {
    const u = safeUrl(current);
    if (!u) break;
    const host = u.hostname.toLowerCase();
    let next: string | null = null;
    if (/(^|\.)google\.[a-z.]+$/.test(host) && u.pathname === '/url') next = u.searchParams.get('q') ?? u.searchParams.get('url');
    else if (host.endsWith('safelinks.protection.outlook.com')) next = u.searchParams.get('url');
    else if (host === 'urldefense.proofpoint.com' && u.searchParams.get('u'))
      next = (u.searchParams.get('u') as string).replace(/_/g, '/').replace(/-([0-9A-F]{2})/g, (_, h: string) => String.fromCharCode(parseInt(h, 16)));
    else if (host === 'urldefense.com' && u.pathname.startsWith('/v3/__')) next = decodeURIComponent(u.pathname.slice(6).split('__;')[0] ?? '');
    else if ((host === 'l.facebook.com' || host === 'lm.facebook.com') && u.pathname === '/l.php') next = u.searchParams.get('u');
    else if (host.endsWith('linkedin.com') && u.pathname.startsWith('/redir/')) next = u.searchParams.get('url');
    else if (host === 'slack-redir.net') next = u.searchParams.get('url');
    else if (host.endsWith('mimecastprotect.com') || host.endsWith('protect-us.mimecast.com')) next = u.searchParams.get('domain') ? `https://${u.searchParams.get('domain')}` : null;
    if (!next || next === current) break;
    wrapper = wrapper ?? host;
    current = next;
  }
  return { url: current, wrapper };
}

const SEGMENT_TOKEN = /^(?=.*\d)(?=.*[a-z])[a-z0-9_-]{12,}$/i;
// Short random ids ("0x9k2", "a8f3b") mix several digits and letters; words like "html5" or "v2" don't.
const SHORT_TOKEN = /^(?=(?:[^\d]*\d){2})(?=(?:[^a-z]*[a-z]){2})[a-z0-9_-]{5,}$/i;

export function urlTemplate(u: URL, regDomain: string | null): string {
  const host = regDomain ?? u.hostname.toLowerCase();
  const segs = u.pathname
    .split('/')
    .filter(Boolean)
    .slice(0, 8)
    .map((s) => {
      const d = (() => {
        try {
          return decodeURIComponent(s);
        } catch {
          return s;
        }
      })();
      if (/^\d+$/.test(d)) return '{n}';
      if (/^[0-9a-f]{8,}$/i.test(d)) return '{hex}';
      if (/^[0-9a-f]{8}-[0-9a-f]{4}-/i.test(d)) return '{uuid}';
      if (d.length >= 24 || SEGMENT_TOKEN.test(d) || SHORT_TOKEN.test(d) || (d.length >= 10 && stringEntropy(d) > 3.6)) return '{tok}';
      if (/@/.test(d)) return '{email}';
      return d.toLowerCase().replace(/\d+/g, '{n}');
    });
  const keys = [...new Set([...u.searchParams.keys()].map((k) => k.toLowerCase()))].sort().slice(0, 8);
  return `${host}/${segs.join('/')}${keys.length ? '?' + keys.join('&') : ''}`;
}

const LOGIN_WORDS = /(log-?in|sign-?in|verify|verification|secure|account|update|confirm|auth|password|webmail|wallet|unlock|recover|validate|billing|invoice|payment|kyc|suspend)/i;
const EXECUTABLE_DOWNLOAD = /\.(exe|scr|msi|bat|cmd|jse?|vbs|vbe|hta|ps1|jar|iso|img|vhdx?|lnk|apk|one|docm|xlsm|pptm|wsf|cpl)$/i;
const ARCHIVE_DOWNLOAD = /\.(zip|rar|7z|gz|tgz|cab)$/i;
// A tracker-style *subdomain* label ("click.brand-mail.com"); never matched against the registrable
// label itself, so "email-verify.xyz" or "click-secure.top" are not excused.
const TRACKER_HOST = /^(click|clicks|clickthru|clickthrough|track|tracking|trk|links?|lnk|email|e|em|mail|mailer|news|newsletter|go|r|t|url\d*|redirect|out|ea|ec|ct|cl)\d*\./i;
const TRACKER_PATH = /\/(click|clickthru|clickthrough|track|trk|redirect|redir|r|c|l|ls|lt|ss|wf)(\/|\.php|\.asp|\?|$)|[?&](url|u|redirect|dest|destination|target|link)=http/i;
const LOOKS_LIKE_URL =/\b((?:https?:\/\/)?(?:[a-z0-9-]+\.)+[a-z]{2,})(?:[/:?#]\S*)?$/i;

function anchorTextDomain(text: string | null | undefined): string | null {
  if (!text) return null;
  const t = text.trim();
  if (t.length > 120 || /\s/.test(t)) return null;
  const m = LOOKS_LIKE_URL.exec(t);
  if (!m) return null;
  const host = (m[1] as string).replace(/^https?:\/\//i, '').toLowerCase();
  const info = hostInfo(host);
  return info.regDomain;
}

export function analyzeLinks(candidates: LinkCandidate[], intel: IntelProvider | null | undefined, unsubscribeUrls: Set<string>): LinkAnalysis[] {
  const byUrl = new Map<string, LinkAnalysis>();
  for (const cand of candidates) {
    const rawUrl = cand.url.trim();
    if (!rawUrl || rawUrl.startsWith('#') || /^(mailto|tel|sms|cid|about):/i.test(rawUrl)) continue;
    const existing = byUrl.get(rawUrl);
    if (existing) {
      if (!existing.sources.includes(cand.source)) existing.sources.push(cand.source);
      if (!existing.displayText && cand.text) existing.displayText = cand.text.trim().slice(0, 200) || null;
      continue;
    }
    const scheme = /^([a-z][a-z0-9+.-]*):/i.exec(rawUrl)?.[1]?.toLowerCase() ?? '';
    if (scheme === 'javascript' || scheme === 'data' || scheme === 'vbscript' || scheme === 'file') {
      byUrl.set(rawUrl, {
        url: rawUrl.slice(0, 300),
        unwrappedFrom: null,
        sources: [cand.source],
        displayText: cand.text?.trim().slice(0, 200) || null,
        scheme,
        host: '',
        unicodeHost: null,
        regDomain: null,
        tld: null,
        isIp: false,
        template: `${scheme}:`,
        flags: [`${scheme}-uri`],
        risk: 3,
        lookalikeOf: null,
        intelHit: null,
      });
      continue;
    }
    const { url, wrapper } = unwrapUrl(rawUrl);
    const u = safeUrl(url);
    if (!u || !/^https?:$/.test(u.protocol)) continue;

    const host = u.hostname.toLowerCase().replace(/^\[|\]$/g, '');
    const info = hostInfo(host);
    const flags: string[] = [];
    let risk = 0;
    const bump = (flag: string, level: number): void => {
      flags.push(flag);
      if (level > risk) risk = level;
    };

    const unicodeHost = toUnicodeHost(host);
    if (info.isIp) bump(isPublicIp(host) ? 'ip-host' : 'private-ip-host', 3);
    if (unicodeHost) bump('punycode', 2);
    if (unicodeHost && hasMixedScriptWord(unicodeHost.replace(/\./g, ' '))) bump('mixed-script', 3);
    if (u.username || u.password || /@/.test(u.host)) bump('credentials-in-url', 3);
    if (u.port && !['80', '443', ''].includes(u.port)) bump('nonstandard-port', 2);
    if (u.protocol === 'http:') flags.push('no-tls');
    const shortener = hostMatchesSuffix(host, URL_SHORTENERS);
    if (shortener) bump('shortener', 1);
    const hosting = hostMatchesSuffix(host, FREE_HOSTING_SUFFIXES);
    if (hosting) bump('free-hosting', 1);
    const formSvc = FORM_SERVICES.find((f) => (host + u.pathname).includes(f));
    if (formSvc) bump('form-service', 1);
    if (info.tld && SUSPICIOUS_TLDS.has(info.tld.split('.').pop() as string)) bump('suspicious-tld', 1);
    if (info.subdomain && info.subdomain.split('.').length >= 4) bump('deep-subdomain', 1);
    if (url.length > 180) flags.push('long-url');
    if (EXECUTABLE_DOWNLOAD.test(u.pathname)) bump('file-download', 2);
    else if (ARCHIVE_DOWNLOAD.test(u.pathname)) bump('archive-download', 1);
    if (u.pathname.toLowerCase().includes('/ipfs/') || host.includes('ipfs')) bump('ipfs', 2);

    const lookalike = detectLookalike(host);
    if (lookalike) bump(`lookalike-${lookalike.kind}`, lookalike.kind === 'homoglyph' || lookalike.kind === 'typosquat' ? 3 : 2);

    if (LOGIN_WORDS.test(host + u.pathname) && !ESP_TRACKING_DOMAINS.has(info.regDomain ?? '')) flags.push('login-keywords');

    // Open redirects: a URL parameter pointing at another site.
    for (const [, v] of u.searchParams) {
      if (/^https?:\/\//i.test(v)) {
        const inner = safeUrl(v);
        if (inner && hostInfo(inner.hostname).regDomain !== info.regDomain) {
          bump('redirect-param', 1);
          break;
        }
      }
    }

    const textDomain = anchorTextDomain(cand.text);
    if (textDomain && info.regDomain && textDomain !== info.regDomain) {
      // Newsletter click-trackers ("click.example-mail.com/…", "…/clickthru?url=") rewrite every link;
      // a mismatch through one of them is bookkeeping, not deception, unless the link is itself suspect.
      const tracker =
        ESP_TRACKING_DOMAINS.has(info.regDomain) || !!wrapper || (!!info.subdomain && TRACKER_HOST.test(host)) || TRACKER_PATH.test(u.pathname + u.search);
      if (tracker && !lookalike && risk < 3) flags.push('text-href-mismatch-tracking');
      else bump('text-href-mismatch', 3);
    }

    const lowerPath = u.pathname.toLowerCase();
    if (/\/(open|opens|track|pixel|beacon|o)\/|\/(blank|open|pixel|spacer|1x1)\.(gif|png)$/.test(lowerPath)) flags.push('tracking');
    if (unsubscribeUrls.has(rawUrl) || /unsub|\/un\/|opt-?out|preferences/.test(lowerPath + u.search.toLowerCase())) flags.push('unsubscribe');
    if (info.regDomain && ESP_TRACKING_DOMAINS.has(info.regDomain)) flags.push('esp-tracking');

    let intelHit: string | null = null;
    if (intel) {
      intelHit = (intel.lookupUrl?.(url) ?? null) || intel.lookupDomain(host) || (info.regDomain ? intel.lookupDomain(info.regDomain) : null);
      if (intelHit) bump('threat-intel', 3);
    }

    byUrl.set(rawUrl, {
      url,
      unwrappedFrom: wrapper ? rawUrl : null,
      sources: [cand.source],
      displayText: cand.text?.trim().slice(0, 200) || null,
      scheme: u.protocol.replace(':', ''),
      host,
      unicodeHost,
      regDomain: info.regDomain,
      tld: info.tld,
      isIp: info.isIp,
      template: urlTemplate(u, info.regDomain),
      flags,
      risk: risk as LinkAnalysis['risk'],
      lookalikeOf: lookalike ? `${lookalike.brand.name} (${lookalike.target})` : null,
      intelHit,
    });
  }
  return [...byUrl.values()];
}
