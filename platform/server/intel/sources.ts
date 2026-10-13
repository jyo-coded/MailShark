// Intelligence source connectors. Each declares what it provides, how it is accessed, its terms,
// its refresh interval and the exact hosts it may contact. Feeds are downloaded in bulk and matched
// locally (no case data leaves the platform); lookups send one indicator to a third-party API and
// therefore run only when a case explicitly enables online lookups (and are audit-logged).
import { createHash } from 'node:crypto';
import { unzipSync } from 'fflate';
import type { IntelConfig } from '../config';
import { fetchResource, type FetchResult } from './http';
import { canonicalUrl, ipv4ToInt, normEmail, normHash, normHost, normIp, normPhone, registrable, type IntelType } from './normalize';
import { ipv6Hex, type EventRow, type IndicatorRow, type IntelHit, type IntelStore } from './store';

export interface SyncContext {
  store: IntelStore;
  config: IntelConfig;
  etag: string | null;
  lastModified: string | null;
  state: Record<string, unknown>;
  log: (msg: string) => void;
}

export interface SyncOutcome {
  status: 'updated' | 'not-modified' | 'partial';
  records: number;
  events?: number;
  bytes: number;
  sha256: string | null;
  etag?: string | null;
  lastModified?: string | null;
  state?: Record<string, unknown>;
  notes?: string[];
}

export interface LookupResult {
  status: 'found' | 'not-found' | 'error' | 'skipped';
  hits: IntelHit[];
  events: Omit<EventRow, 'indicators'>[];
  detail: string;
}

export interface Connector {
  id: string;
  name: string;
  provider: string;
  kind: 'feed' | 'enrichment' | 'lookup';
  homepage: string;
  license: string;
  /** What the source lists, and at what granularity. */
  provides: string;
  /** Whether records name a campaign / event / malware family (vs. a bare indicator list). */
  attribution: 'campaign-events' | 'malware-family' | 'indicator-only' | 'enrichment';
  access: 'public' | 'free-key' | 'key-optional' | 'self-hosted';
  intervalHours: number;
  hosts: string[];
  requires?: (keyof IntelConfig)[];
  defaultEnabled: boolean;
  sync?: (ctx: SyncContext) => Promise<SyncOutcome>;
  lookupTypes?: IntelType[];
  lookup?: (ctx: { store: IntelStore; config: IntelConfig }, type: IntelType, value: string) => Promise<LookupResult>;
}

// ── Parsing helpers ──────────────────────────────────────────────────────────

const sha = (b: Uint8Array): string => createHash('sha256').update(b).digest('hex');

function utc(s: string | null | undefined): number | null {
  if (!s) return null;
  const t = Date.parse(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}(:\d{2})?$/.test(s.trim()) ? s.trim().replace(' ', 'T') + 'Z' : s.trim());
  return Number.isNaN(t) ? null : t;
}

/** Minimal RFC 4180 CSV parser (quotes, doubled quotes, optional spaces after commas). */
export function parseCsvLine(line: string): string[] {
  const out: string[] = [];
  let i = 0;
  while (i <= line.length) {
    while (line[i] === ' ') i++;
    if (line[i] === '"') {
      let v = '';
      i++;
      while (i < line.length) {
        if (line[i] === '"') {
          if (line[i + 1] === '"') {
            v += '"';
            i += 2;
            continue;
          }
          i++;
          break;
        }
        v += line[i++];
      }
      out.push(v);
      while (i < line.length && line[i] !== ',') i++;
      i++;
    } else {
      const j = line.indexOf(',', i);
      out.push((j < 0 ? line.slice(i) : line.slice(i, j)).trim());
      i = j < 0 ? line.length + 1 : j + 1;
    }
  }
  return out;
}

function* dataLines(text: string): Generator<string> {
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (line && !line.startsWith('#')) yield line;
  }
}

function unzipFirst(bytes: Uint8Array, want: RegExp = /./): string {
  const files = unzipSync(bytes);
  const name = Object.keys(files).find((n) => want.test(n)) ?? Object.keys(files)[0];
  if (!name) throw new Error('empty zip archive');
  return Buffer.from(files[name] as Uint8Array).toString('utf8');
}

async function download(ctx: SyncContext, c: Connector, url: string, maxBytes = 400 * 1024 * 1024): Promise<FetchResult> {
  return fetchResource(url, { allowedHosts: c.hosts, etag: ctx.etag, lastModified: ctx.lastModified, maxBytes, timeoutMs: 300_000 });
}

/** Drop domain-level entries that would flag popular sites (same rule as feeds/build_feeds.py). */
function dropPopular(store: IntelStore, rows: IndicatorRow[]): { kept: IndicatorRow[]; dropped: number } {
  const tenants = new Map<string, number>();
  for (const r of rows) {
    if (r.type !== 'domain') continue;
    const reg = registrable(r.value);
    if (reg && reg !== r.value) tenants.set(reg, (tenants.get(reg) ?? 0) + 1);
  }
  const kept: IndicatorRow[] = [];
  let dropped = 0;
  for (const r of rows) {
    if (r.type !== 'domain') {
      kept.push(r);
      continue;
    }
    const reg = registrable(r.value);
    const rank = store.popularity(reg);
    if (rank === null || !reg) kept.push(r);
    else if (r.value === reg && rank <= 100_000) dropped++;
    else if (r.value !== reg && rank <= 1_000 && (tenants.get(reg) ?? 0) < 10) dropped++;
    else kept.push(r);
  }
  return { kept, dropped };
}

function finish(ctx: SyncContext, res: FetchResult, records: number, extra: Partial<SyncOutcome> = {}): SyncOutcome {
  return { status: 'updated', records, bytes: res.bytes.length, sha256: sha(res.bytes), etag: res.etag, lastModified: res.lastModified, ...extra };
}

const notModified = (ctx: SyncContext): SyncOutcome => ({ status: 'not-modified', records: -1, bytes: 0, sha256: null, etag: ctx.etag, lastModified: ctx.lastModified });

// ── Feeds ────────────────────────────────────────────────────────────────────

const urlhaus: Connector = {
  id: 'urlhaus',
  name: 'URLhaus (malware URLs)',
  provider: 'abuse.ch',
  kind: 'feed',
  homepage: 'https://urlhaus.abuse.ch/',
  license: 'Free under the abuse.ch fair-use terms (commercial use may require a subscription): https://urlhaus.abuse.ch/api/',
  provides: 'URLs serving malware, with threat type, tags (often the malware family), status and dates.',
  attribution: 'malware-family',
  access: 'public',
  intervalHours: 6,
  hosts: ['urlhaus.abuse.ch'],
  defaultEnabled: true,
  async sync(ctx) {
    const res = await download(ctx, this, 'https://urlhaus.abuse.ch/downloads/csv/');
    if (res.notModified) return notModified(ctx);
    const text = unzipFirst(res.bytes, /\.(txt|csv)$/);
    const rows: IndicatorRow[] = [];
    for (const line of dataLines(text)) {
      const [id, added, url, status, lastOnline, threat, tags, link] = parseCsvLine(line);
      const c = url ? canonicalUrl(url) : null;
      if (!c) continue;
      rows.push({ type: 'url', value: c, firstSeen: utc(added), lastSeen: utc(lastOnline) ?? utc(added), threat: threat || 'malware_download', family: null, tags: tags && tags !== 'None' ? tags : null, reference: link || null, externalId: id || null, extra: status || null });
    }
    return finish(ctx, res, ctx.store.replaceIndicators(this.id, rows));
  },
};

const urlhausHosts: Connector = {
  id: 'urlhaus-hosts',
  name: 'URLhaus host file',
  provider: 'abuse.ch',
  kind: 'feed',
  homepage: 'https://urlhaus.abuse.ch/api/#hostfile',
  license: urlhaus.license,
  provides: 'Host names used for malware distribution. Curated by abuse.ch to exclude hosts shared with legitimate content.',
  attribution: 'indicator-only',
  access: 'public',
  intervalHours: 6,
  hosts: ['urlhaus.abuse.ch'],
  defaultEnabled: true,
  async sync(ctx) {
    const res = await download(ctx, this, 'https://urlhaus.abuse.ch/downloads/hostfile/');
    if (res.notModified) return notModified(ctx);
    const rows: IndicatorRow[] = [];
    for (const line of dataLines(res.bytes.toString('utf8'))) {
      const h = normHost(line.split(/\s+/).pop() ?? '');
      if (h) rows.push({ type: 'domain', value: h, threat: 'malware_download' });
    }
    const { kept, dropped } = dropPopular(ctx.store, rows);
    return finish(ctx, res, ctx.store.replaceIndicators(this.id, kept), { notes: dropped ? [`${dropped} popular-site entries dropped`] : [] });
  },
};

const threatfox: Connector = {
  id: 'threatfox',
  name: 'ThreatFox (IOCs with malware attribution)',
  provider: 'abuse.ch',
  kind: 'feed',
  homepage: 'https://threatfox.abuse.ch/',
  license: 'Free under the abuse.ch fair-use terms: https://threatfox.abuse.ch/api/',
  provides: 'Domains, URLs, IP:port pairs and file hashes linked to a named malware family, with confidence level, first/last seen and reference.',
  attribution: 'malware-family',
  access: 'public',
  intervalHours: 6,
  hosts: ['threatfox.abuse.ch'],
  defaultEnabled: true,
  async sync(ctx) {
    const res = await download(ctx, this, 'https://threatfox.abuse.ch/export/json/full/');
    if (res.notModified) return notModified(ctx);
    const json = JSON.parse(unzipFirst(res.bytes, /\.json$/)) as Record<string, { ioc_value: string; ioc_type: string; threat_type: string; malware_printable: string; malware_alias: string | null; first_seen_utc: string; last_seen_utc: string | null; confidence_level: number; reference: string | null; tags: string | null }[]>;
    const rows: IndicatorRow[] = [];
    for (const [id, list] of Object.entries(json)) {
      for (const e of list) {
        let type: IntelType | null = null;
        let value: string | null = null;
        let extra: string | null = null;
        if (e.ioc_type === 'domain') ((type = 'domain'), (value = normHost(e.ioc_value)));
        else if (e.ioc_type === 'url') ((type = 'url'), (value = canonicalUrl(e.ioc_value)));
        else if (e.ioc_type === 'ip:port') {
          const [ip, port] = e.ioc_value.split(/:(?=\d+$)/);
          type = 'ip';
          value = ip ? normIp(ip) : null;
          extra = port ? `port ${port}` : null;
        } else if (e.ioc_type === 'md5_hash') ((type = 'md5'), (value = normHash('md5', e.ioc_value)));
        else if (e.ioc_type === 'sha1_hash') ((type = 'sha1'), (value = normHash('sha1', e.ioc_value)));
        else if (e.ioc_type === 'sha256_hash') ((type = 'sha256'), (value = normHash('sha256', e.ioc_value)));
        if (!type || !value) continue;
        rows.push({
          type,
          value,
          firstSeen: utc(e.first_seen_utc),
          lastSeen: utc(e.last_seen_utc) ?? utc(e.first_seen_utc),
          threat: e.threat_type,
          family: e.malware_printable || null,
          tags: [e.malware_alias, e.tags].filter(Boolean).join('; ') || null,
          confidence: e.confidence_level,
          reference: e.reference || `https://threatfox.abuse.ch/ioc/${id}/`,
          externalId: id,
          extra,
        });
      }
    }
    const { kept, dropped } = dropPopular(ctx.store, rows);
    return finish(ctx, res, ctx.store.replaceIndicators(this.id, kept), { notes: dropped ? [`${dropped} popular-site entries dropped`] : [] });
  },
};

const malwareBazaar: Connector = {
  id: 'malwarebazaar',
  name: 'MalwareBazaar (malware sample hashes)',
  provider: 'abuse.ch',
  kind: 'feed',
  homepage: 'https://bazaar.abuse.ch/',
  license: 'Free under the abuse.ch fair-use terms: https://bazaar.abuse.ch/faq/#tos',
  provides: 'SHA-256/SHA-1/MD5 of confirmed malware samples with signature (family), file name and type. Default: last 48 hours; MAILSHARK_BAZAAR_FULL=1 imports the full history.',
  attribution: 'malware-family',
  access: 'public',
  intervalHours: 4,
  hosts: ['bazaar.abuse.ch'],
  defaultEnabled: true,
  async sync(ctx) {
    const full = ctx.config.bazaarFull;
    const res = await download(ctx, this, full ? 'https://bazaar.abuse.ch/export/csv/full/' : 'https://bazaar.abuse.ch/export/csv/recent/', 600 * 1024 * 1024);
    if (res.notModified) return notModified(ctx);
    const text = full ? unzipFirst(res.bytes, /\.csv$/) : res.bytes.toString('utf8');
    const rows: IndicatorRow[] = [];
    for (const line of dataLines(text)) {
      const [first, s256, m5, s1, , fileName, fileType, , signature] = parseCsvLine(line);
      const seen = utc(first);
      const family = signature && signature !== 'n/a' ? signature : null;
      const extra = [fileName, fileType].filter((x) => x && x !== 'n/a').join(' · ') || null;
      const ref = s256 ? `https://bazaar.abuse.ch/sample/${s256}/` : null;
      for (const [t, v] of [['sha256', s256], ['md5', m5], ['sha1', s1]] as const) {
        const n = v ? normHash(t, v) : null;
        if (n) rows.push({ type: t, value: n, firstSeen: seen, lastSeen: seen, threat: 'malware', family, reference: ref, externalId: s256 ?? null, extra });
      }
    }
    // The recent window replaces itself; history accumulates when not importing the full dump.
    const n = full ? ctx.store.replaceIndicators(this.id, rows) : ctx.store.db.tx(() => ctx.store.insertIndicators(this.id, rows));
    return finish(ctx, res, n, { notes: full ? [] : ['Recent 48-hour export; earlier entries are kept across syncs.'] });
  },
};

const feodo: Connector = {
  id: 'feodo',
  name: 'Feodo Tracker (botnet C2 servers)',
  provider: 'abuse.ch',
  kind: 'feed',
  homepage: 'https://feodotracker.abuse.ch/',
  license: 'Free under the abuse.ch fair-use terms: https://feodotracker.abuse.ch/blocklist/',
  provides: 'IP addresses of botnet command-and-control servers (Emotet, QakBot, Dridex, …) with malware family, ASN and dates.',
  attribution: 'malware-family',
  access: 'public',
  intervalHours: 6,
  hosts: ['feodotracker.abuse.ch'],
  defaultEnabled: true,
  async sync(ctx) {
    const res = await download(ctx, this, 'https://feodotracker.abuse.ch/downloads/ipblocklist.json');
    if (res.notModified) return notModified(ctx);
    const list = JSON.parse(res.bytes.toString('utf8')) as { ip_address: string; port: number; status: string; malware: string; first_seen: string; last_online: string | null; as_name: string | null }[];
    const rows: IndicatorRow[] = [];
    for (const e of list) {
      const ip = normIp(e.ip_address);
      if (ip) rows.push({ type: 'ip', value: ip, firstSeen: utc(e.first_seen), lastSeen: utc(e.last_online), threat: 'botnet_cc', family: e.malware, tags: e.as_name, extra: `port ${e.port}, ${e.status}`, reference: `https://feodotracker.abuse.ch/browse/host/${ip}/` });
    }
    return finish(ctx, res, ctx.store.replaceIndicators(this.id, rows));
  },
};

const openphish: Connector = {
  id: 'openphish',
  name: 'OpenPhish community feed',
  provider: 'OpenPhish',
  kind: 'feed',
  homepage: 'https://openphish.com/phishing_feeds.html',
  license: 'Community feed, free under the OpenPhish Terms of Use (commercial use limited): https://openphish.com/terms.html',
  provides: 'Currently active phishing URLs (updated every 12 hours). No brand or campaign data in the community feed.',
  attribution: 'indicator-only',
  access: 'public',
  intervalHours: 12,
  // openphish.com/feed.txt now answers with a 302 to the project's GitHub repository; fetch that directly.
  hosts: ['raw.githubusercontent.com'],
  defaultEnabled: true,
  async sync(ctx) {
    const res = await download(ctx, this, 'https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt');
    if (res.notModified) return notModified(ctx);
    const now = Date.now();
    const rows: IndicatorRow[] = [];
    for (const line of dataLines(res.bytes.toString('utf8'))) {
      const c = canonicalUrl(line);
      if (c) rows.push({ type: 'url', value: c, firstSeen: now, lastSeen: now, threat: 'phishing' });
    }
    // The feed is a moving window: keep URLs from previous windows, refresh last_seen for current ones.
    const prev = new Map(ctx.store.db.all<{ value: string; first_seen: number | null }>("SELECT value, first_seen FROM indicators WHERE source = 'openphish'").map((r) => [r.value, r.first_seen]));
    for (const r of rows) r.firstSeen = prev.get(r.value) ?? now;
    const n = ctx.store.db.tx(() => ctx.store.insertIndicators(this.id, rows));
    return finish(ctx, res, n + prev.size - rows.filter((r) => prev.has(r.value)).length, { notes: [`${rows.length} URLs in the current window`] });
  },
};

const phishingDatabase: Connector = {
  id: 'phishing-database',
  name: 'Phishing.Database (active phishing domains and links)',
  provider: 'Phishing.Database project (Mitchell Krog et al.)',
  kind: 'feed',
  homepage: 'https://github.com/Phishing-Database/Phishing.Database',
  license: 'MIT',
  provides: 'Domains (and, by default, URLs) currently classified active by the project’s tests. Popular sites are filtered out (Tranco).',
  attribution: 'indicator-only',
  access: 'public',
  intervalHours: 24,
  hosts: ['raw.githubusercontent.com'],
  defaultEnabled: true,
  async sync(ctx) {
    const base = 'https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/';
    const res = await download(ctx, this, base + 'phishing-domains-ACTIVE.txt');
    const rows: IndicatorRow[] = [];
    if (!res.notModified) {
      for (const line of dataLines(res.bytes.toString('utf8'))) {
        const h = normHost(line);
        if (h) rows.push({ type: 'domain', value: h, threat: 'phishing' });
      }
    }
    let bytes = res.bytes.length;
    const hashes = [sha(res.bytes)];
    if (ctx.config.phishingDbLinks) {
      const links = await fetchResource(base + 'phishing-links-ACTIVE.txt', { allowedHosts: this.hosts, maxBytes: 400 * 1024 * 1024, timeoutMs: 600_000 });
      bytes += links.bytes.length;
      hashes.push(sha(links.bytes));
      for (const line of dataLines(links.bytes.toString('utf8'))) {
        const c = canonicalUrl(line);
        if (c) rows.push({ type: 'url', value: c, threat: 'phishing' });
      }
    }
    if (res.notModified && !ctx.config.phishingDbLinks) return notModified(ctx);
    const { kept, dropped } = dropPopular(ctx.store, rows);
    const n = ctx.store.replaceIndicators(this.id, kept);
    return { status: 'updated', records: n, bytes, sha256: createHash('sha256').update(hashes.join(':')).digest('hex'), etag: res.etag, lastModified: res.lastModified, notes: dropped ? [`${dropped} popular-site entries dropped`] : [] };
  },
};

const spamhausDrop: Connector = {
  id: 'spamhaus-drop',
  name: 'Spamhaus DROP (hijacked / criminal netblocks)',
  provider: 'Spamhaus',
  kind: 'feed',
  homepage: 'https://www.spamhaus.org/blocklists/do-not-route-or-peer/',
  license: 'Free to use; see https://www.spamhaus.org/drop/ (no redistribution of the list itself)',
  provides: 'IPv4 netblocks controlled by spammers or cyber-criminals. A sending IP inside one is strong context for the origin.',
  attribution: 'indicator-only',
  access: 'public',
  intervalHours: 24,
  hosts: ['www.spamhaus.org'],
  defaultEnabled: true,
  async sync(ctx) {
    const res = await download(ctx, this, 'https://www.spamhaus.org/drop/drop_v4.json');
    if (res.notModified) return notModified(ctx);
    const rows: { start: number; end: number; cidr: string; label: string | null; reference: string | null }[] = [];
    for (const line of dataLines(res.bytes.toString('utf8'))) {
      let o: { cidr?: string; sblid?: string };
      try {
        o = JSON.parse(line) as { cidr?: string; sblid?: string };
      } catch {
        continue;
      }
      if (!o.cidr) continue;
      const [ip, bits] = o.cidr.split('/');
      const start = ip ? ipv4ToInt(ip) : null;
      const b = Number(bits);
      if (start === null || !(b >= 0 && b <= 32)) continue;
      const size = 2 ** (32 - b);
      rows.push({ start, end: start + size - 1, cidr: o.cidr, label: o.sblid ?? null, reference: o.sblid ? `https://check.spamhaus.org/sbl/query/${o.sblid}` : null });
    }
    return finish(ctx, res, ctx.store.replaceCidrs(this.id, rows));
  },
};

const torExits: Connector = {
  id: 'tor-exits',
  name: 'Tor exit relays',
  provider: 'The Tor Project',
  kind: 'feed',
  homepage: 'https://check.torproject.org/',
  license: 'Public data published by the Tor Project',
  provides: 'Current Tor exit relay addresses: context for an anonymised client or sender IP (not evidence of malice).',
  attribution: 'indicator-only',
  access: 'public',
  intervalHours: 6,
  hosts: ['check.torproject.org'],
  defaultEnabled: true,
  async sync(ctx) {
    const res = await download(ctx, this, 'https://check.torproject.org/torbulkexitlist');
    if (res.notModified) return notModified(ctx);
    const now = Date.now();
    const rows: IndicatorRow[] = [];
    for (const line of dataLines(res.bytes.toString('utf8'))) {
      const ip = normIp(line);
      if (ip) rows.push({ type: 'ip', value: ip, threat: 'tor-exit', lastSeen: now });
    }
    return finish(ctx, res, ctx.store.replaceIndicators(this.id, rows));
  },
};

const phishtank: Connector = {
  id: 'phishtank',
  name: 'PhishTank (verified phishing URLs)',
  provider: 'Cisco Talos / OpenDNS',
  kind: 'feed',
  homepage: 'https://phishtank.org/developer_info.php',
  license: 'Free with an application key under the PhishTank terms',
  provides: 'Community-verified phishing URLs with the targeted brand and verification time.',
  attribution: 'indicator-only',
  access: 'free-key',
  intervalHours: 6,
  hosts: ['data.phishtank.com'],
  requires: ['phishtankAppKey'],
  defaultEnabled: true,
  async sync(ctx) {
    const key = encodeURIComponent(ctx.config.phishtankAppKey ?? '');
    const res = await download(ctx, this, `https://data.phishtank.com/data/${key}/online-valid.json`);
    if (res.notModified) return notModified(ctx);
    const list = JSON.parse(res.bytes.toString('utf8')) as { phish_id: number; url: string; phish_detail_url: string; submission_time: string; verification_time: string; target: string }[];
    const rows: IndicatorRow[] = [];
    for (const e of list) {
      const c = canonicalUrl(e.url);
      if (c) rows.push({ type: 'url', value: c, firstSeen: utc(e.submission_time), lastSeen: utc(e.verification_time), threat: 'phishing', family: e.target && e.target !== 'Other' ? `target: ${e.target}` : null, reference: e.phish_detail_url, externalId: String(e.phish_id) });
    }
    return finish(ctx, res, ctx.store.replaceIndicators(this.id, rows));
  },
};

// ── MISP feeds (campaign / event records) ────────────────────────────────────

interface MispAttribute {
  type: string;
  category?: string;
  value: string;
  to_ids?: boolean;
  comment?: string;
}

/** Maps a MISP attribute to normalised indicators (attacker-side values only). */
export function mispIndicators(a: MispAttribute): { type: IntelType; value: string; reference?: string }[] {
  const t = a.type;
  const v = (a.value ?? '').trim();
  if (!v) return [];
  const one = (type: IntelType, value: string | null): { type: IntelType; value: string }[] => (value ? [{ type, value }] : []);
  if (t === 'link' || ((t === 'url' || t === 'uri') && /external analysis/i.test(a.category ?? ''))) return [];
  if (t === 'url' || t === 'uri') return one('url', canonicalUrl(v));
  if (t === 'domain' || t === 'hostname') return one('domain', normHost(v));
  if (t === 'domain|ip') {
    const [d, ip] = v.split('|');
    return [...one('domain', normHost(d ?? '')), ...one('ip', normIp(ip ?? ''))];
  }
  if (t === 'hostname|port') return one('domain', normHost(v.split('|')[0] ?? ''));
  if (/^ip-(src|dst)(\|port)?$/.test(t)) return one('ip', normIp(v.split('|')[0] ?? ''));
  if (['email', 'email-src', 'email-reply-to', 'email-dst', 'whois-registrant-email'].includes(t)) return one('email', normEmail(v));
  if (t === 'md5' || t === 'sha1' || t === 'sha256') return one(t, normHash(t, v));
  const fh = /^filename\|(md5|sha1|sha256)$/.exec(t);
  if (fh) {
    const [name, hash] = v.split('|');
    const ht = fh[1] as 'md5' | 'sha1' | 'sha256';
    return [...one(ht, normHash(ht, hash ?? '')), ...(name ? [{ type: 'filename' as IntelType, value: name.toLowerCase() }] : [])];
  }
  if (t === 'malware-sample') {
    const [, hash] = v.split('|');
    return one('md5', normHash('md5', hash ?? ''));
  }
  if (t === 'email-subject') return [{ type: 'subject', value: v.toLowerCase().replace(/\s+/g, ' ').slice(0, 300) }];
  if (t === 'email-attachment' || t === 'filename') return [{ type: 'filename', value: v.toLowerCase().slice(0, 300) }];
  if (t === 'btc') return [{ type: 'btc', value: v }];
  if (t === 'phone-number' || t === 'whois-registrant-phone') return one('phone', normPhone(v));
  return [];
}

function mispFeed(id: string, name: string, provider: string, base: string, homepage: string): Connector {
  const host = new URL(base).hostname;
  return {
    id,
    name,
    provider,
    kind: 'feed',
    homepage,
    license: 'MISP OSINT feed, events tagged TLP:WHITE/TLP:CLEAR (shareable without restriction)',
    provides: 'Documented threat events (campaign reports, phishing operations) with their indicators: URLs, domains, IPs, e-mail addresses, subjects, attachment hashes, wallets.',
    attribution: 'campaign-events',
    access: 'public',
    intervalHours: 12,
    hosts: [host],
    defaultEnabled: true,
    async sync(ctx) {
      const res = await fetchResource(base + 'manifest.json', { allowedHosts: this.hosts, etag: ctx.etag, lastModified: ctx.lastModified, maxBytes: 64 * 1024 * 1024 });
      const pending = (ctx.state['pending'] as number | undefined) ?? 0;
      if (res.notModified && !pending) return notModified(ctx);
      const manifest = res.notModified
        ? ((ctx.state['manifest'] as Record<string, { timestamp: string; date: string }>) ?? {})
        : (JSON.parse(res.bytes.toString('utf8')) as Record<string, { info: string; date: string; timestamp: string | number }>);
      const since = Date.parse(ctx.config.mispFeedSince + 'T00:00:00Z');
      const known = ctx.store.eventTimestamps(id);
      const wanted = Object.entries(manifest)
        .map(([uuid, m]) => ({ uuid, ts: Number(m.timestamp) * 1000, date: Date.parse(String(m.date) + 'T00:00:00Z') }))
        .filter((e) => !(e.date < since));
      const wantedIds = new Set(wanted.map((e) => e.uuid));
      const stale = [...known.keys()].filter((k) => !wantedIds.has(k));
      if (stale.length) ctx.store.removeEvents(id, stale);
      const todo = wanted.filter((e) => (known.get(e.uuid) ?? -1) < e.ts).sort((a, b) => b.ts - a.ts);
      const batch = todo.slice(0, ctx.config.mispFeedBatch);
      let imported = 0;
      let bytes = res.bytes.length;
      const errors: string[] = [];
      for (const e of batch) {
        try {
          const ev = await fetchResource(`${base}${e.uuid}.json`, { allowedHosts: this.hosts, maxBytes: 64 * 1024 * 1024, retries: 1 });
          bytes += ev.bytes.length;
          const doc = JSON.parse(ev.bytes.toString('utf8')) as { Event: { uuid: string; info: string; date: string; timestamp: string; threat_level_id?: string; Orgc?: { name?: string }; Tag?: { name: string }[]; Attribute?: MispAttribute[]; Object?: { Attribute?: MispAttribute[] }[] } };
          const evt = doc.Event;
          const attrs = [...(evt.Attribute ?? []), ...(evt.Object ?? []).flatMap((o) => o.Attribute ?? [])];
          const report = attrs.find((a) => a.type === 'link' && /^https?:\/\//.test(a.value))?.value ?? null;
          const indicators: EventRow['indicators'] = [];
          for (const a of attrs) for (const ind of mispIndicators(a)) indicators.push({ type: ind.type, value: ind.value, category: a.category ?? null, toIds: !!a.to_ids, comment: a.comment ?? null });
          ctx.store.upsertEvent(id, {
            id: evt.uuid ?? e.uuid,
            name: evt.info,
            date: Date.parse(evt.date + 'T00:00:00Z') || null,
            updatedAt: Number(evt.timestamp) * 1000 || e.ts,
            org: evt.Orgc?.name ?? null,
            tags: (evt.Tag ?? []).map((t) => t.name).slice(0, 60),
            threatLevel: evt.threat_level_id ? Number(evt.threat_level_id) : null,
            reference: report ?? `${base}${e.uuid}.json`,
            indicators,
          });
          imported++;
        } catch (err) {
          errors.push(`${e.uuid}: ${err instanceof Error ? err.message : String(err)}`);
          if (errors.length >= 10) break;
        }
        await new Promise((r) => setTimeout(r, 150)); // be polite to the feed host
      }
      const remaining = todo.length - imported;
      const events = ctx.store.db.get<{ n: number }>('SELECT COUNT(*) AS n FROM events WHERE source = ?', id)?.n ?? 0;
      const records = ctx.store.db.get<{ n: number }>('SELECT COUNT(*) AS n FROM event_indicators WHERE source = ?', id)?.n ?? 0;
      return {
        status: remaining > 0 ? 'partial' : 'updated',
        records,
        events,
        bytes,
        sha256: res.notModified ? null : sha(res.bytes),
        etag: res.etag,
        lastModified: res.lastModified,
        state: { pending: remaining, manifest: res.notModified ? manifest : Object.fromEntries(Object.entries(manifest).map(([k, m]) => [k, { timestamp: String(m.timestamp), date: String(m.date) }])) },
        notes: [`${imported} events imported this run${remaining > 0 ? `, ${remaining} remaining (next runs continue)` : ''}`, ...errors.slice(0, 3)],
      };
    },
  };
}

const circl = mispFeed('circl-osint', 'CIRCL OSINT feed (MISP)', 'CIRCL (Computer Incident Response Center Luxembourg)', 'https://www.circl.lu/doc/misp/feed-osint/', 'https://www.circl.lu/doc/misp/feed-osint/');
const botvrij = mispFeed('botvrij', 'Botvrij.eu OSINT feed (MISP)', 'Botvrij.eu', 'https://www.botvrij.eu/data/feed-osint/', 'https://www.botvrij.eu/data/');

// ── Enrichment ───────────────────────────────────────────────────────────────

const tranco: Connector = {
  id: 'tranco',
  name: 'Tranco top sites',
  provider: 'Tranco (Le Pochat et al., NDSS 2019)',
  kind: 'enrichment',
  homepage: 'https://tranco-list.eu/',
  license: 'Free for research and commercial use (see https://tranco-list.eu/)',
  provides: 'Popularity rank of registrable domains. Used only to discount indicators shared with popular sites, never as a trust verdict.',
  attribution: 'enrichment',
  access: 'public',
  intervalHours: 24 * 7,
  hosts: ['tranco-list.eu'],
  defaultEnabled: true,
  async sync(ctx) {
    const res = await download(ctx, this, 'https://tranco-list.eu/top-1m.csv.zip');
    if (res.notModified) return notModified(ctx);
    const text = unzipFirst(res.bytes, /\.csv$/);
    function* rows(): Generator<[string, number]> {
      for (const line of text.split(/\r?\n/)) {
        const i = line.indexOf(',');
        if (i < 0) continue;
        const rank = Number(line.slice(0, i));
        const d = line.slice(i + 1).trim().toLowerCase();
        if (rank > 0 && d) yield [d, rank];
      }
    }
    return finish(ctx, res, ctx.store.replacePopular(rows()));
  },
};

const asn: Connector = {
  id: 'asn',
  name: 'IP → ASN (iptoasn.com)',
  provider: 'iptoasn.com, via the ip-location-db package on jsDelivr',
  kind: 'enrichment',
  homepage: 'https://iptoasn.com/',
  license: 'Public Domain Dedication and License (PDDL)',
  provides: 'Autonomous system number and name for IPv4/IPv6 addresses: who operates the sending infrastructure.',
  attribution: 'enrichment',
  access: 'public',
  intervalHours: 24 * 7,
  hosts: ['cdn.jsdelivr.net'],
  defaultEnabled: true,
  async sync(ctx) {
    const base = 'https://cdn.jsdelivr.net/npm/@ip-location-db/iptoasn-asn/';
    const r4 = await download(ctx, this, base + 'iptoasn-asn-ipv4.csv');
    if (r4.notModified) return notModified(ctx);
    const r6 = await fetchResource(base + 'iptoasn-asn-ipv6.csv', { allowedHosts: this.hosts, maxBytes: 200 * 1024 * 1024 });
    function* v4(): Generator<[number, number, number, string]> {
      for (const line of r4.bytes.toString('utf8').split(/\r?\n/)) {
        if (!line) continue;
        const [s, e, a, name] = parseCsvLine(line);
        const si = s ? ipv4ToInt(s) : null;
        const ei = e ? ipv4ToInt(e) : null;
        if (si !== null && ei !== null) yield [si, ei, Number(a) || 0, name ?? ''];
      }
    }
    function* v6(): Generator<[string, string, number, string]> {
      for (const line of r6.bytes.toString('utf8').split(/\r?\n/)) {
        if (!line) continue;
        const [s, e, a, name] = parseCsvLine(line);
        const sh = s ? ipv6Hex(s.toLowerCase()) : null;
        const eh = e ? ipv6Hex(e.toLowerCase()) : null;
        if (sh && eh) yield [sh, eh, Number(a) || 0, name ?? ''];
      }
    }
    const n = ctx.store.replaceAsn(v4(), v6());
    return { status: 'updated', records: n, bytes: r4.bytes.length + r6.bytes.length, sha256: createHash('sha256').update(r4.bytes).update(r6.bytes).digest('hex'), etag: r4.etag, lastModified: r4.lastModified };
  },
};

// ── Online lookups (opt-in per case; each call is audit-logged) ──────────────

class RateLimiter {
  private stamps: number[] = [];
  constructor(
    private readonly max: number,
    private readonly windowMs: number,
  ) {}
  async take(): Promise<void> {
    for (;;) {
      const now = Date.now();
      this.stamps = this.stamps.filter((t) => now - t < this.windowMs);
      if (this.stamps.length < this.max) {
        this.stamps.push(now);
        return;
      }
      await new Promise((r) => setTimeout(r, this.windowMs - (now - (this.stamps[0] as number)) + 50));
    }
  }
}

const otxLimiter = new RateLimiter(60, 60_000);
const vtLimiter = new RateLimiter(4, 60_000);
const abusechLimiter = new RateLimiter(30, 60_000);
// Your own MISP server: polite default; TLS is always verified (use NODE_EXTRA_CA_CERTS for a private CA).
const mispLimiter = new RateLimiter(60, 60_000);

const otx: Connector = {
  id: 'otx',
  name: 'AlienVault OTX (pulses)',
  provider: 'LevelBlue / AT&T Alien Labs Open Threat Exchange',
  kind: 'lookup',
  homepage: 'https://otx.alienvault.com/api',
  license: 'Free; OTX terms of service. An API key (OTX_API_KEY) raises rate limits.',
  provides: 'Pulses: community and vendor reports, from named campaign write-ups (adversary, malware family, references) to automated daily indicator dumps, which are recognised and treated as listings, not campaigns.',
  attribution: 'campaign-events',
  access: 'key-optional',
  intervalHours: 0,
  hosts: ['otx.alienvault.com'],
  defaultEnabled: true,
  lookupTypes: ['domain', 'ip', 'url', 'md5', 'sha1', 'sha256'],
  async lookup(ctx, type, value) {
    const section = type === 'domain' ? (registrable(value) === value ? 'domain' : 'hostname') : type === 'ip' ? (value.includes(':') ? 'IPv6' : 'IPv4') : type === 'url' ? 'url' : 'file';
    const url = `https://otx.alienvault.com/api/v1/indicators/${section}/${encodeURIComponent(value)}/general`;
    await otxLimiter.take();
    const res = await fetchResource(url, { allowedHosts: this.hosts, headers: ctx.config.otxApiKey ? { 'X-OTX-API-KEY': ctx.config.otxApiKey } : {}, timeoutMs: 30_000, maxBytes: 8 * 1024 * 1024, retries: 1 });
    const j = JSON.parse(res.bytes.toString('utf8')) as { pulse_info?: { count?: number; pulses?: { id: string; name: string; created: string; modified: string; tags?: string[]; references?: string[]; adversary?: string; malware_families?: ({ display_name?: string } | string)[]; author_name?: string }[] } };
    const pulses = j.pulse_info?.pulses ?? [];
    if (!pulses.length) return { status: 'not-found', hits: [], events: [], detail: 'No OTX pulse references this indicator.' };
    return {
      status: 'found',
      hits: [],
      events: pulses.slice(0, 25).map((p) => ({
        id: p.id,
        name: p.name,
        date: Date.parse(p.created) || null,
        updatedAt: Date.parse(p.modified) || null,
        org: p.author_name ?? null,
        tags: [...(p.tags ?? []), ...(p.adversary ? [`adversary:${p.adversary}`] : []), ...(p.malware_families ?? []).map((m) => `malware:${typeof m === 'string' ? m : (m.display_name ?? '')}`)].slice(0, 40),
        threatLevel: null,
        reference: p.references?.[0] ?? `https://otx.alienvault.com/pulse/${p.id}`,
      })),
      detail: `${j.pulse_info?.count ?? pulses.length} OTX pulse(s) reference this indicator.`,
    };
  },
};

const virustotal: Connector = {
  id: 'virustotal',
  name: 'VirusTotal',
  provider: 'Google / VirusTotal',
  kind: 'lookup',
  homepage: 'https://docs.virustotal.com/reference/overview',
  license: 'Public API under the VirusTotal terms (non-commercial use; 4 requests/min). Requires VT_API_KEY.',
  provides: 'Multi-engine verdicts, reputation, popular threat label and tags for files, URLs, domains and IPs.',
  attribution: 'malware-family',
  access: 'free-key',
  intervalHours: 0,
  hosts: ['www.virustotal.com'],
  requires: ['virusTotalApiKey'],
  defaultEnabled: true,
  lookupTypes: ['domain', 'ip', 'url', 'md5', 'sha1', 'sha256'],
  async lookup(ctx, type, value) {
    const id = type === 'url' ? Buffer.from(value).toString('base64url') : encodeURIComponent(value);
    const path = type === 'domain' ? 'domains' : type === 'ip' ? 'ip_addresses' : type === 'url' ? 'urls' : 'files';
    await vtLimiter.take();
    let res: FetchResult;
    try {
      res = await fetchResource(`https://www.virustotal.com/api/v3/${path}/${id}`, { allowedHosts: this.hosts, headers: { 'x-apikey': ctx.config.virusTotalApiKey ?? '' }, timeoutMs: 30_000, maxBytes: 16 * 1024 * 1024, retries: 1 });
    } catch (e) {
      if ((e as { status?: number }).status === 404) return { status: 'not-found', hits: [], events: [], detail: 'Unknown to VirusTotal.' };
      throw e;
    }
    const a = (JSON.parse(res.bytes.toString('utf8')) as { data?: { attributes?: Record<string, unknown> } }).data?.attributes ?? {};
    const stats = (a['last_analysis_stats'] ?? {}) as Record<string, number>;
    const malicious = stats['malicious'] ?? 0;
    const suspicious = stats['suspicious'] ?? 0;
    const label = ((a['popular_threat_classification'] ?? {}) as { suggested_threat_label?: string }).suggested_threat_label ?? null;
    const first = (a['first_submission_date'] ?? a['creation_date']) as number | undefined;
    const hit: IntelHit = {
      source: 'virustotal',
      type,
      value,
      matchType: 'exact',
      firstSeen: first ? first * 1000 : null,
      lastSeen: (a['last_analysis_date'] as number | undefined) ? (a['last_analysis_date'] as number) * 1000 : null,
      threat: malicious >= 3 ? 'malicious' : malicious + suspicious > 0 ? 'some-detections' : 'no-detections',
      family: label,
      tags: Array.isArray(a['tags']) ? (a['tags'] as string[]).slice(0, 20).join(', ') : null,
      confidence: malicious,
      reference: `https://www.virustotal.com/gui/${type === 'url' ? 'url' : type === 'domain' ? 'domain' : type === 'ip' ? 'ip-address' : 'file'}/${type === 'url' ? createHash('sha256').update(value).digest('hex') : value}`,
      externalId: null,
      suppressed: null,
    };
    return { status: 'found', hits: [hit], events: [], detail: `${malicious} engine(s) flag it as malicious, ${suspicious} as suspicious.` };
  },
};

const mispInstance: Connector = {
  id: 'misp',
  name: 'MISP instance',
  provider: 'Your organisation’s MISP server',
  kind: 'lookup',
  homepage: 'https://www.misp-project.org/',
  license: 'Governed by your MISP sharing groups / TLP',
  provides: 'Events (campaigns, incidents) from your MISP instance that contain the indicator, with tags and galaxies.',
  attribution: 'campaign-events',
  access: 'self-hosted',
  intervalHours: 0,
  hosts: [],
  requires: ['mispUrl', 'mispApiKey'],
  defaultEnabled: true,
  lookupTypes: ['domain', 'ip', 'url', 'email', 'md5', 'sha1', 'sha256', 'btc', 'phone'],
  async lookup(ctx, _type, value) {
    const base = ctx.config.mispUrl as string;
    await mispLimiter.take();
    const res = await fetchResource(`${base}/attributes/restSearch`, {
      allowedHosts: [new URL(base).hostname],
      allowHttp: base.startsWith('http:'),
      method: 'POST',
      headers: { authorization: ctx.config.mispApiKey ?? '', accept: 'application/json', 'content-type': 'application/json' },
      body: JSON.stringify({ value, returnFormat: 'json', includeEventTags: true, limit: 50 }),
      timeoutMs: 30_000,
      maxBytes: 32 * 1024 * 1024,
      retries: 1,
    });
    const j = JSON.parse(res.bytes.toString('utf8')) as { response?: { Attribute?: { event_id: string; Event?: { info?: string; uuid?: string; date?: string; Orgc?: { name?: string } }; Tag?: { name: string }[] }[] } };
    const attrs = j.response?.Attribute ?? [];
    if (!attrs.length) return { status: 'not-found', hits: [], events: [], detail: 'No MISP attribute matches.' };
    const seen = new Map<string, LookupResult['events'][number]>();
    for (const at of attrs) {
      const uuid = at.Event?.uuid ?? at.event_id;
      if (seen.has(uuid)) continue;
      seen.set(uuid, { id: uuid, name: at.Event?.info ?? `Event ${at.event_id}`, date: at.Event?.date ? Date.parse(at.Event.date) : null, updatedAt: null, org: at.Event?.Orgc?.name ?? null, tags: (at.Tag ?? []).map((t) => t.name).slice(0, 30), threatLevel: null, reference: `${base}/events/view/${at.event_id}` });
    }
    return { status: 'found', hits: [], events: [...seen.values()], detail: `${seen.size} MISP event(s) contain this value.` };
  },
};

const bazaarApi: Connector = {
  id: 'malwarebazaar-api',
  name: 'MalwareBazaar API (hash history)',
  provider: 'abuse.ch',
  kind: 'lookup',
  homepage: 'https://bazaar.abuse.ch/api/',
  license: 'Free under the abuse.ch fair-use terms; requires an Auth-Key (ABUSECH_AUTH_KEY)',
  provides: 'Full sample history for a hash: signature (family), first seen, file name, delivery method, tags.',
  attribution: 'malware-family',
  access: 'free-key',
  intervalHours: 0,
  hosts: ['mb-api.abuse.ch'],
  requires: ['abusechAuthKey'],
  defaultEnabled: true,
  lookupTypes: ['md5', 'sha1', 'sha256'],
  async lookup(ctx, type, value) {
    await abusechLimiter.take();
    const res = await fetchResource('https://mb-api.abuse.ch/api/v1/', {
      allowedHosts: this.hosts,
      method: 'POST',
      headers: { 'Auth-Key': ctx.config.abusechAuthKey ?? '', 'content-type': 'application/x-www-form-urlencoded' },
      body: `query=get_info&hash=${encodeURIComponent(value)}`,
      timeoutMs: 30_000,
      maxBytes: 8 * 1024 * 1024,
      retries: 1,
    });
    const j = JSON.parse(res.bytes.toString('utf8')) as { query_status: string; data?: { sha256_hash: string; signature: string | null; first_seen: string; last_seen: string | null; file_name: string; tags: string[] | null; delivery_method: string | null }[] };
    if (j.query_status !== 'ok' || !j.data?.length) return { status: 'not-found', hits: [], events: [], detail: `MalwareBazaar: ${j.query_status}` };
    const d = j.data[0] as NonNullable<typeof j.data>[number];
    return {
      status: 'found',
      hits: [{ source: 'malwarebazaar-api', type, value, matchType: 'exact', firstSeen: utc(d.first_seen), lastSeen: utc(d.last_seen), threat: 'malware', family: d.signature, tags: [...(d.tags ?? []), d.delivery_method ? `delivery:${d.delivery_method}` : ''].filter(Boolean).join(', '), confidence: null, reference: `https://bazaar.abuse.ch/sample/${d.sha256_hash}/`, externalId: d.sha256_hash, suppressed: null }],
      events: [],
      detail: `Known sample${d.signature ? ` (${d.signature})` : ''}, first seen ${d.first_seen}.`,
    };
  },
};

export const CONNECTORS: Connector[] = [tranco, asn, urlhaus, urlhausHosts, threatfox, malwareBazaar, feodo, openphish, phishingDatabase, spamhausDrop, torExits, phishtank, circl, botvrij, otx, virustotal, mispInstance, bazaarApi];

export function connector(id: string): Connector | undefined {
  return CONNECTORS.find((c) => c.id === id);
}

export function missingRequirements(c: Connector, cfg: IntelConfig): string[] {
  const names: Record<string, string> = { otxApiKey: 'OTX_API_KEY', virusTotalApiKey: 'VT_API_KEY', mispUrl: 'MISP_URL', mispApiKey: 'MISP_API_KEY', abusechAuthKey: 'ABUSECH_AUTH_KEY', phishtankAppKey: 'PHISHTANK_APP_KEY' };
  return (c.requires ?? []).filter((k) => !cfg[k]).map((k) => names[k] ?? String(k));
}
