// Domain, host and IP helpers built on the Public Suffix List (tldts).
import { parse as tldParse } from 'tldts';

export interface HostInfo {
  host: string;
  regDomain: string | null; // registrable domain (eTLD+1)
  tld: string | null;
  subdomain: string;
  isIp: boolean;
}

export function hostInfo(hostRaw: string): HostInfo {
  const host = hostRaw.trim().toLowerCase().replace(/\.$/, '').replace(/^\[|\]$/g, '');
  const p = tldParse(host, { allowPrivateDomains: false });
  const isIp = !!p.isIp || isIpLiteral(host);
  return {
    host,
    regDomain: isIp ? null : (p.domain ?? null),
    tld: isIp ? null : (p.publicSuffix ?? null),
    subdomain: isIp ? '' : (p.subdomain ?? ''),
    isIp,
  };
}

/** Registrable ("organizational") domain, or the host itself if unknown. */
export function orgDomain(host: string | null | undefined): string {
  if (!host) return '';
  const info = hostInfo(host);
  return info.regDomain ?? info.host;
}

/** Same as orgDomain but uses private PSL entries too (e.g. `foo.github.io`, `x.web.app`). */
export function siteDomain(host: string): string {
  const p = tldParse(host.toLowerCase(), { allowPrivateDomains: true });
  return p.domain ?? host.toLowerCase();
}

export function domainOfAddress(addr: string | null | undefined): string {
  if (!addr) return '';
  const at = addr.lastIndexOf('@');
  return at >= 0 ? addr.slice(at + 1).trim().toLowerCase().replace(/[>\s].*$/, '') : '';
}

// ── IP helpers ──────────────────────────────────────────────────────────────

export function isIpLiteral(s: string): boolean {
  return isIPv4(s) || isIPv6(s);
}

export function isIPv4(s: string): boolean {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s);
  return !!m && m.slice(1).every((o) => Number(o) <= 255);
}

export function isIPv6(s: string): boolean {
  return /^[0-9a-f:]+$/i.test(s) && s.includes(':') && s.split(':').length >= 3 && s.split(':').length <= 9;
}

export function isPublicIp(ip: string): boolean {
  if (isIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number) as [number, number];
    if (a === 10 || a === 127 || a === 0) return false;
    if (a === 172 && b >= 16 && b <= 31) return false;
    if (a === 192 && b === 168) return false;
    if (a === 169 && b === 254) return false;
    if (a === 100 && b >= 64 && b <= 127) return false;
    if (a >= 224) return false;
    return true;
  }
  if (isIPv6(ip)) {
    const l = ip.toLowerCase();
    if (l === '::1' || l.startsWith('fe80') || l.startsWith('fc') || l.startsWith('fd') || l === '::') return false;
    return true;
  }
  return false;
}

/** /24 for IPv4, /48 for IPv6: the "neighbourhood" used for infrastructure correlation. */
export function ipNetwork(ip: string): string | null {
  if (isIPv4(ip)) return ip.split('.').slice(0, 3).join('.') + '.0/24';
  if (isIPv6(ip)) {
    const full = expandIPv6(ip);
    return full ? full.split(':').slice(0, 3).join(':') + '::/48' : null;
  }
  return null;
}

function expandIPv6(ip: string): string | null {
  const parts = ip.split('::');
  if (parts.length > 2) return null;
  const head = parts[0] ? parts[0].split(':') : [];
  const tail = parts.length === 2 && parts[1] ? parts[1].split(':') : [];
  const missing = 8 - head.length - tail.length;
  if (missing < 0) return null;
  const all = [...head, ...new Array<string>(parts.length === 2 ? missing : 0).fill('0'), ...tail];
  if (all.length !== 8) return null;
  return all.map((h) => h.padStart(4, '0').toLowerCase()).join(':');
}

// ── Punycode (RFC 3492) decoder: shows the real characters behind xn-- labels ──

const BASE = 36;
const TMIN = 1;
const TMAX = 26;
const SKEW = 38;
const DAMP = 700;
const INITIAL_BIAS = 72;
const INITIAL_N = 128;

function adapt(delta: number, numPoints: number, firstTime: boolean): number {
  let k = 0;
  delta = firstTime ? Math.floor(delta / DAMP) : delta >> 1;
  delta += Math.floor(delta / numPoints);
  for (; delta > ((BASE - TMIN) * TMAX) >> 1; k += BASE) delta = Math.floor(delta / (BASE - TMIN));
  return Math.floor(k + ((BASE - TMIN + 1) * delta) / (delta + SKEW));
}

function basicToDigit(cp: number): number {
  if (cp >= 0x30 && cp < 0x3a) return 26 + (cp - 0x30);
  if (cp >= 0x41 && cp < 0x5b) return cp - 0x41;
  if (cp >= 0x61 && cp < 0x7b) return cp - 0x61;
  return BASE;
}

export function punycodeDecodeLabel(input: string): string | null {
  const output: number[] = [];
  let i = 0;
  let n = INITIAL_N;
  let bias = INITIAL_BIAS;
  let basic = input.lastIndexOf('-');
  if (basic < 0) basic = 0;
  for (let j = 0; j < basic; j++) {
    if (input.charCodeAt(j) >= 0x80) return null;
    output.push(input.charCodeAt(j));
  }
  for (let idx = basic > 0 ? basic + 1 : 0; idx < input.length; ) {
    const oldi = i;
    for (let w = 1, k = BASE; ; k += BASE) {
      if (idx >= input.length) return null;
      const digit = basicToDigit(input.charCodeAt(idx++));
      if (digit >= BASE) return null;
      i += digit * w;
      const t = k <= bias ? TMIN : k >= bias + TMAX ? TMAX : k - bias;
      if (digit < t) break;
      w *= BASE - t;
      if (w > 0x7fffffff) return null;
    }
    const out = output.length + 1;
    bias = adapt(i - oldi, out, oldi === 0);
    n += Math.floor(i / out);
    i %= out;
    if (n > 0x10ffff) return null;
    output.splice(i++, 0, n);
  }
  try {
    return String.fromCodePoint(...output);
  } catch {
    return null;
  }
}

export function toUnicodeHost(host: string): string | null {
  if (!/(^|\.)xn--/i.test(host)) return null;
  const labels = host.split('.').map((l) => (l.toLowerCase().startsWith('xn--') ? (punycodeDecodeLabel(l.slice(4)) ?? l) : l));
  return labels.join('.');
}

// ── Reference lists ─────────────────────────────────────────────────────────

export const FREEMAIL = new Set([
  'gmail.com', 'googlemail.com', 'yahoo.com', 'yahoo.co.in', 'yahoo.co.uk', 'ymail.com', 'rocketmail.com', 'outlook.com',
  'hotmail.com', 'hotmail.co.uk', 'live.com', 'msn.com', 'aol.com', 'icloud.com', 'me.com', 'mac.com', 'proton.me',
  'protonmail.com', 'pm.me', 'gmx.com', 'gmx.de', 'gmx.net', 'web.de', 'mail.com', 'mail.ru', 'yandex.com', 'yandex.ru',
  'zoho.com', 'zohomail.com', 'tutanota.com', 'tuta.io', 'rediffmail.com', 'qq.com', '163.com', '126.com', 'sina.com',
  'naver.com', 'daum.net', 'hanmail.net', 'libero.it', 'laposte.net', 'orange.fr', 'free.fr', 'seznam.cz', 'wp.pl',
  'o2.pl', 'interia.pl', 't-online.de', 'bk.ru', 'inbox.ru', 'list.ru', 'rambler.ru', 'hushmail.com', 'fastmail.com',
  'mailfence.com', 'onmail.com', 'aim.com', 'att.net', 'comcast.net', 'verizon.net', 'sbcglobal.net', 'bellsouth.net',
  'cox.net', 'earthlink.net', 'juno.com', 'optonline.net', 'charter.net', 'btinternet.com', 'sky.com', 'virginmedia.com',
  'bigpond.com', 'shaw.ca', 'rogers.com', 'sympatico.ca', 'yahoo.fr', 'yahoo.de', 'yahoo.es', 'yahoo.it', 'yahoo.com.br',
  'hotmail.fr', 'hotmail.it', 'hotmail.es', 'outlook.in', 'outlook.fr', 'live.in', 'live.co.uk', 'mailinator.com',
  'guerrillamail.com', 'sharklasers.com', 'temp-mail.org', '10minutemail.com', 'yopmail.com', 'dispostable.com',
]);

export const URL_SHORTENERS = new Set([
  'bit.ly', 'bitly.com', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'rebrand.ly', 'cutt.ly', 'shorturl.at',
  'rb.gy', 't.ly', 'tiny.cc', 'lnkd.in', 'bl.ink', 'short.io', 'soo.gd', 's.id', 'v.gd', 'qrco.de', 'shorturl.asia',
  'clck.ru', 'u.to', 'x.gd', 'urlz.fr', 'surl.li', 'tinu.be', 'hyperurl.co', 'lnk.bio', 'linktr.ee', 'bit.do', 'db.tt',
  'adf.ly', 'shorte.st', 'ouo.io', 'snip.ly', 'mcaf.ee', 'go2l.ink', 'qr.io', 'me-qr.com', 'l.ead.me', 'did.li',
]);

/** Platforms that let anyone host a page on a trusted-looking domain; heavily abused for credential phishing. */
export const FREE_HOSTING_SUFFIXES = [
  'web.app', 'firebaseapp.com', 'pages.dev', 'workers.dev', 'github.io', 'gitlab.io', 'netlify.app', 'vercel.app',
  'glitch.me', 'weebly.com', 'weeblysite.com', 'wixsite.com', 'wix.com', 'blogspot.com', 'wordpress.com', 'godaddysites.com',
  'squarespace.com', 'webflow.io', 'herokuapp.com', 'onrender.com', 'fly.dev', 'repl.co', 'replit.app', 'replit.dev',
  'azurewebsites.net', 'blob.core.windows.net', 'web.core.windows.net', 'azureedge.net', 'storage.googleapis.com',
  'appspot.com', 'r2.dev', 's3.amazonaws.com', 'amplifyapp.com', 'cloudfront.net', '000webhostapp.com', 'ngrok.io',
  'ngrok-free.app', 'ngrok.app', 'trycloudflare.com', 'loca.lt', 'serveo.net', 'duckdns.org', 'ddns.net', 'no-ip.org',
  'myftp.biz', 'hopto.org', 'zapto.org', 'sytes.net', 'ipfs.io', 'dweb.link', 'cloudflare-ipfs.com', 'fleek.co',
  'jimdosite.com', 'strikingly.com', 'yolasite.com', 'site123.me', 'mystrikingly.com', 'carrd.co', 'tilda.ws',
  'notion.site', 'canva.site', 'my.canva.site', 'sharepoint.com', 'onedrive.live.com', '1drv.ms', 'dropboxusercontent.com',
  'surge.sh', 'deno.dev', 'workers.dev', 'framer.website', 'framer.app', 'bubbleapps.io', 'typedream.app', 'wixstudio.com',
];

/** Form/document services frequently abused to collect credentials. */
export const FORM_SERVICES = [
  'forms.gle', 'docs.google.com/forms', 'forms.office.com', 'forms.microsoft.com', 'jotform.com', 'typeform.com',
  'formstack.com', 'wufoo.com', 'surveymonkey.com', 'zohoforms.com', 'cognitoforms.com', 'formsite.com', '123formbuilder.com',
];

/** TLDs with persistently high abuse rates in phishing research (Spamhaus / Interisle reports). */
export const SUSPICIOUS_TLDS = new Set([
  'zip', 'mov', 'top', 'xyz', 'icu', 'click', 'quest', 'cfd', 'sbs', 'rest', 'gq', 'tk', 'ml', 'cf', 'ga', 'buzz', 'cyou',
  'monster', 'bond', 'lol', 'mom', 'beauty', 'hair', 'skin', 'makeup', 'autos', 'boats', 'yachts', 'motorcycles', 'homes',
  'support', 'live', 'online', 'site', 'website', 'fun', 'space', 'store', 'shop', 'work', 'today', 'digital', 'loan',
  'win', 'bid', 'date', 'racing', 'download', 'stream', 'party', 'review', 'trade', 'accountant', 'science', 'men', 'kim',
  'country', 'gdn', 'cam', 'uno', 'pw', 'su', 'best', 'run', 'ink', 'life', 'world', 'info', 'biz', 'ru', 'cn',
]);

/** Click-tracking / redirect domains operated by legitimate email service providers. */
export const ESP_TRACKING_DOMAINS = new Set([
  'sendgrid.net', 'list-manage.com', 'mcsv.net', 'mailchi.mp', 'mandrillapp.com', 'mailgun.org', 'mailgun.net',
  'sparkpostmail.com', 'awstrack.me', 'amazonses.com', 'rs6.net', 'constantcontact.com', 'hubspotlinks.com',
  'hubspotemail.net', 'hs-sites.com', 'hubspot.com', 'klclick.com', 'klclick1.com', 'klclick2.com', 'klclick3.com',
  'klaviyomail.com', 'mlsend.com', 'mlsend2.com', 'mailerlite.com', 'sendibt2.com', 'sendibt3.com', 'sendibm1.com',
  'brevo.com', 'r.mailjet.com', 'mjt.lu', 'exacttarget.com', 'salesforce.com', 'marketingcloudapps.com', 'eloqua.com',
  'en25.com', 'mktoweb.com', 'mkt-mail.com', 'marketo.com', 'mailjet.com', 'postmarkapp.com', 'pstmrk.it', 'cmail19.com',
  'cmail20.com', 'createsend.com', 'createsend1.com', 'customeriomail.com', 'customer.io', 'intercom-clicks.com',
  'intercom-mail.com', 'zohocampaigns.com', 'zcsend.net', 'maillist-manage.com', 'mlrctk.com', 'mailercloud.com',
  'benchmarkemail.com', 'bmetrack.com', 'aweber.com', 'getresponse.com', 'gr8.com', 'activehosted.com', 'acemlna.com',
  'acemlnb.com', 'acemlnc.com', 'acemlnd.com', 'moosend.com', 'omnisend.com', 'omnisnippet1.com', 'sendinblue.com',
  'substack.com', 'beehiiv.com', 'convertkit-mail.com', 'ck.page', 'kit.com', 'emltrk.com', 'rsgsv.net', 'ctctcdn.com',
  'urldefense.com', 'urldefense.proofpoint.com', 'mimecast.com', 'mimecastprotect.com', 'mailchimp.com',
  'sailthru.com', 'iterable.com', 'braze.com', 'braze-images.com', 'bnc.lt', 'app.link', 'smore.com', 'sendpulse.com',
]);

export function isFreemail(domain: string): boolean {
  return FREEMAIL.has(domain.toLowerCase());
}

export function hostMatchesSuffix(host: string, suffixes: Iterable<string>): string | null {
  const h = host.toLowerCase();
  for (const s of suffixes) {
    if (s.includes('/')) continue;
    if (h === s || h.endsWith('.' + s)) return s;
  }
  return null;
}
