// Read/write access to intel.db. Matching is exact after normalisation; every hit carries the
// listing's provenance (source, first/last seen, threat, family, reference). Hits that are almost
// certainly not attributable to an attacker (a popular site's apex domain, a shared hosting
// platform's own domain) are returned with a `suppressed` reason instead of being silently dropped,
// so an investigator can see that the listing exists and why it was not counted.
import { createHash } from 'node:crypto';
import { Db, type Param } from '../db/sqlite';
import { INTEL_MIGRATIONS } from './schema';
import { canonicalUrl, hostCandidates, hostOfUrl, ipv4ToInt, normIp, registrable, urlWithoutQuery, type IntelType } from './normalize';
import { FREE_HOSTING_SUFFIXES, URL_SHORTENERS, isIPv4, isIPv6 } from '../../../engine/src/util/domain';

export type MatchType = 'exact' | 'exact-url' | 'url-without-query' | 'host' | 'parent-domain' | 'host-of-listed-url' | 'cidr';

export interface IntelHit {
  source: string;
  type: string;
  value: string;
  matchType: MatchType;
  firstSeen: number | null;
  lastSeen: number | null;
  threat: string | null;
  family: string | null;
  tags: string | null;
  confidence: number | null;
  reference: string | null;
  externalId: string | null;
  suppressed: 'popular-domain' | 'shared-platform' | null;
}

export interface EventHit {
  source: string;
  eventId: string;
  name: string;
  date: number | null;
  updatedAt: number | null;
  org: string | null;
  tags: string[];
  threatLevel: number | null;
  reference: string | null;
  type: string;
  value: string;
  category: string | null;
  toIds: boolean;
  matchType: MatchType;
  suppressed: IntelHit['suppressed'];
}

export interface IndicatorRow {
  type: IntelType;
  value: string;
  firstSeen?: number | null;
  lastSeen?: number | null;
  threat?: string | null;
  family?: string | null;
  tags?: string | null;
  confidence?: number | null;
  reference?: string | null;
  externalId?: string | null;
  extra?: string | null;
}

export interface EventRow {
  id: string;
  name: string;
  date: number | null;
  updatedAt: number | null;
  org: string | null;
  tags: string[];
  threatLevel: number | null;
  reference: string | null;
  indicators: { type: IntelType; value: string; category: string | null; toIds: boolean; comment: string | null }[];
}

export interface SourceStatusRow {
  id: string;
  enabled: number;
  last_attempt: number | null;
  last_success: number | null;
  last_error: string | null;
  etag: string | null;
  last_modified: string | null;
  record_count: number;
  event_count: number;
  snapshot_sha256: string | null;
  next_due: number | null;
  state_json: string | null;
}

const POPULAR_TOP = 100_000;
const SHARED_PLATFORMS = new Set([...FREE_HOSTING_SUFFIXES, ...URL_SHORTENERS]);

interface IndicatorDbRow {
  source: string;
  type: string;
  value: string;
  first_seen: number | null;
  last_seen: number | null;
  threat: string | null;
  family: string | null;
  tags: string | null;
  confidence: number | null;
  reference: string | null;
  external_id: string | null;
}

export class IntelStore {
  readonly db: Db;

  constructor(path: string, opts: { readOnly?: boolean } = {}) {
    this.db = new Db(path, opts);
    if (!opts.readOnly) this.db.migrate(INTEL_MIGRATIONS);
  }

  close(): void {
    this.db.close();
  }

  // ── Read side ──────────────────────────────────────────────────────────────

  popularity(domain: string | null): number | null {
    if (!domain) return null;
    return this.db.get<{ rank: number }>('SELECT rank FROM popular WHERE domain = ?', domain)?.rank ?? null;
  }

  private toHit(r: IndicatorDbRow, matchType: MatchType, suppressed: IntelHit['suppressed'] = null): IntelHit {
    return {
      source: r.source,
      type: r.type,
      value: r.value,
      matchType,
      firstSeen: r.first_seen,
      lastSeen: r.last_seen,
      threat: r.threat,
      family: r.family,
      tags: r.tags,
      confidence: r.confidence,
      reference: r.reference,
      externalId: r.external_id,
      suppressed,
    };
  }

  private enabledSources(): Set<string> {
    return new Set(this.db.all<{ id: string }>('SELECT id FROM sources WHERE enabled = 1').map((r) => r.id));
  }

  private rows(type: string, values: string[]): IndicatorDbRow[] {
    if (!values.length) return [];
    const enabled = this.enabledSources();
    const ph = values.map(() => '?').join(',');
    return this.db.all<IndicatorDbRow>(`SELECT * FROM indicators WHERE type = ? AND value IN (${ph})`, type, ...values).filter((r) => enabled.has(r.source));
  }

  /** Why a host-level listing should not count against an email that links to `entry`. */
  private hostSuppression(entry: string, isParentMatch: boolean): IntelHit['suppressed'] {
    const reg = registrable(entry);
    if (reg && entry === reg) {
      const rank = this.popularity(reg);
      if (rank !== null && rank <= POPULAR_TOP) return 'popular-domain';
      if (SHARED_PLATFORMS.has(reg)) return 'shared-platform';
    }
    if (isParentMatch && SHARED_PLATFORMS.has(entry)) return 'shared-platform';
    return null;
  }

  lookupUrl(url: string): IntelHit[] {
    const c = canonicalUrl(url);
    if (!c) return [];
    const exact = this.rows('url', [c]).map((r) => this.toHit(r, 'exact-url'));
    if (exact.length) return exact;
    const base = urlWithoutQuery(c);
    return this.rows('url', [...new Set([base, base + '/'])].filter((v) => v !== c)).map((r) => this.toHit(r, 'url-without-query'));
  }

  /** Host-level lists (domains) for the host and its parent domains. */
  lookupHost(hostRaw: string): IntelHit[] {
    const host = hostRaw.toLowerCase();
    if (isIPv4(host) || isIPv6(host)) return this.lookupIp(host);
    const cands = hostCandidates(host);
    return this.rows('domain', cands).map((r) => {
      const parent = r.value !== host.replace(/^www\./, '');
      return this.toHit(r, parent ? 'parent-domain' : 'host', this.hostSuppression(r.value, parent));
    });
  }

  /** URLs listed on the same host (weaker than a listing of the URL itself). */
  listedUrlsOnHost(hostRaw: string, limit = 5): IntelHit[] {
    const host = hostRaw.toLowerCase();
    const enabled = this.enabledSources();
    const out: IntelHit[] = [];
    const reg = registrable(host);
    const rank = this.popularity(reg);
    const suppressed: IntelHit['suppressed'] = rank !== null && rank <= POPULAR_TOP ? 'popular-domain' : SHARED_PLATFORMS.has(host) ? 'shared-platform' : null;
    for (const scheme of ['http://', 'https://']) {
      const lo = `${scheme}${host}`;
      const rows = this.db.all<IndicatorDbRow>(
        "SELECT * FROM indicators WHERE type = 'url' AND value >= ? AND value < ? LIMIT ?",
        lo,
        lo + '\u{10FFFF}',
        limit * 4,
      );
      for (const r of rows) {
        if (!enabled.has(r.source)) continue;
        if (hostOfUrl(r.value) !== host) continue;
        out.push(this.toHit(r, 'host-of-listed-url', suppressed));
        if (out.length >= limit) return out;
      }
    }
    return out;
  }

  lookupIp(ipRaw: string): IntelHit[] {
    const ip = normIp(ipRaw);
    if (!ip) return [];
    const hits = this.rows('ip', [ip]).map((r) => this.toHit(r, 'exact'));
    const n = ipv4ToInt(ip);
    if (n !== null) {
      const enabled = this.enabledSources();
      const ranges = this.db.all<{ source: string; start: number; end: number; cidr: string; label: string | null; reference: string | null }>(
        'SELECT * FROM cidr4 WHERE start <= ? AND end >= ? ORDER BY start DESC LIMIT 5',
        n,
        n,
      );
      for (const r of ranges) {
        if (!enabled.has(r.source)) continue;
        hits.push({
          source: r.source,
          type: 'cidr',
          value: r.cidr,
          matchType: 'cidr',
          firstSeen: null,
          lastSeen: null,
          threat: 'hijacked-or-criminal-netblock',
          family: null,
          tags: r.label,
          confidence: null,
          reference: r.reference,
          externalId: r.label,
          suppressed: null,
        });
      }
    }
    return hits;
  }

  lookupExact(type: 'md5' | 'sha1' | 'sha256' | 'email' | 'phone' | 'btc', value: string): IntelHit[] {
    return this.rows(type, [value.toLowerCase()]).map((r) => this.toHit(r, 'exact'));
  }

  /** Campaign/event records that list this indicator. Host lookups include parent domains. */
  lookupEvents(type: IntelType, valueRaw: string): EventHit[] {
    let candidates: { value: string; matchType: MatchType; suppressed: IntelHit['suppressed'] }[] = [];
    if (type === 'domain') {
      const host = valueRaw.toLowerCase();
      candidates = hostCandidates(host).map((v) => {
        const parent = v !== host.replace(/^www\./, '');
        return { value: v, matchType: parent ? 'parent-domain' : 'host', suppressed: this.hostSuppression(v, parent) };
      });
    } else if (type === 'url') {
      const c = canonicalUrl(valueRaw);
      if (!c) return [];
      const base = urlWithoutQuery(c);
      candidates = [
        { value: c, matchType: 'exact-url', suppressed: null },
        ...[base, base + '/'].filter((v) => v !== c).map((v) => ({ value: v, matchType: 'url-without-query' as MatchType, suppressed: null })),
      ];
    } else candidates = [{ value: valueRaw.toLowerCase(), matchType: 'exact', suppressed: null }];
    if (!candidates.length) return [];
    const enabled = this.enabledSources();
    const ph = candidates.map(() => '?').join(',');
    const rows = this.db.all<{
      source: string;
      event_id: string;
      type: string;
      value: string;
      category: string | null;
      to_ids: number | null;
      name: string;
      date: number | null;
      updated_at: number | null;
      org: string | null;
      tags: string | null;
      threat_level: number | null;
      reference: string | null;
    }>(
      `SELECT ei.source, ei.event_id, ei.type, ei.value, ei.category, ei.to_ids, e.name, e.date, e.updated_at, e.org, e.tags, e.threat_level, e.reference
       FROM event_indicators ei JOIN events e ON e.source = ei.source AND e.id = ei.event_id
       WHERE ei.type = ? AND ei.value IN (${ph}) LIMIT 50`,
      type,
      ...candidates.map((c) => c.value),
    );
    return rows
      .filter((r) => enabled.has(r.source))
      .map((r) => {
        const cand = candidates.find((c) => c.value === r.value) ?? candidates[0];
        return {
          source: r.source,
          eventId: r.event_id,
          name: r.name,
          date: r.date,
          updatedAt: r.updated_at,
          org: r.org,
          tags: r.tags ? (JSON.parse(r.tags) as string[]) : [],
          threatLevel: r.threat_level,
          reference: r.reference,
          type: r.type,
          value: r.value,
          category: r.category,
          toIds: r.to_ids === 1,
          matchType: cand?.matchType ?? 'exact',
          suppressed: cand?.suppressed ?? null,
        };
      });
  }

  event(source: string, id: string): (EventRow & { attributeCount: number }) | null {
    const e = this.db.get<{ id: string; name: string; date: number | null; updated_at: number | null; org: string | null; tags: string | null; threat_level: number | null; reference: string | null; attribute_count: number }>(
      'SELECT * FROM events WHERE source = ? AND id = ?',
      source,
      id,
    );
    if (!e) return null;
    const inds = this.db.all<{ type: IntelType; value: string; category: string | null; to_ids: number | null; comment: string | null }>(
      'SELECT type, value, category, to_ids, comment FROM event_indicators WHERE source = ? AND event_id = ? LIMIT 2000',
      source,
      id,
    );
    return {
      id: e.id,
      name: e.name,
      date: e.date,
      updatedAt: e.updated_at,
      org: e.org,
      tags: e.tags ? (JSON.parse(e.tags) as string[]) : [],
      threatLevel: e.threat_level,
      reference: e.reference,
      attributeCount: e.attribute_count,
      indicators: inds.map((i) => ({ type: i.type, value: i.value, category: i.category, toIds: i.to_ids === 1, comment: i.comment })),
    };
  }

  asn(ipRaw: string): { asn: number; name: string | null } | null {
    const ip = normIp(ipRaw);
    if (!ip) return null;
    const n = ipv4ToInt(ip);
    if (n !== null) {
      const r = this.db.get<{ start: number; end: number; asn: number; name: string | null }>('SELECT * FROM asn4 WHERE start <= ? ORDER BY start DESC LIMIT 1', n);
      return r && r.end >= n && r.asn > 0 ? { asn: r.asn, name: r.name } : null;
    }
    const hex = ipv6Hex(ip);
    if (!hex) return null;
    const r = this.db.get<{ start: string; end: string; asn: number; name: string | null }>('SELECT * FROM asn6 WHERE start <= ? ORDER BY start DESC LIMIT 1', hex);
    return r && r.end >= hex && r.asn > 0 ? { asn: r.asn, name: r.name } : null;
  }

  sourceStatus(): SourceStatusRow[] {
    return this.db.all<SourceStatusRow>('SELECT * FROM sources ORDER BY id');
  }

  /** Identifies the intelligence state an analysis used (recorded with every result). */
  snapshotId(): string {
    const rows = this.db.all<{ id: string; last_success: number | null; snapshot_sha256: string | null; record_count: number; enabled: number }>(
      'SELECT id, last_success, snapshot_sha256, record_count, enabled FROM sources ORDER BY id',
    );
    return createHash('sha256').update(JSON.stringify(rows)).digest('hex').slice(0, 32);
  }

  // ── Write side (sync worker and lookups) ───────────────────────────────────

  ensureSource(id: string, enabled: boolean): void {
    this.db.run('INSERT OR IGNORE INTO sources (id, enabled) VALUES (?, ?)', id, enabled ? 1 : 0);
  }

  setEnabled(id: string, enabled: boolean): void {
    this.db.run('UPDATE sources SET enabled = ? WHERE id = ?', enabled ? 1 : 0, id);
  }

  sourceRow(id: string): SourceStatusRow | undefined {
    return this.db.get<SourceStatusRow>('SELECT * FROM sources WHERE id = ?', id);
  }

  updateSource(id: string, patch: Partial<Omit<SourceStatusRow, 'id'>>): void {
    const keys = Object.keys(patch) as (keyof typeof patch)[];
    if (!keys.length) return;
    this.db.run(`UPDATE sources SET ${keys.map((k) => `${k} = ?`).join(', ')} WHERE id = ?`, ...keys.map((k) => (patch[k] ?? null) as Param), id);
  }

  /** Replaces every indicator of a source in one transaction (readers keep the old snapshot until commit). */
  replaceIndicators(source: string, rows: Iterable<IndicatorRow>): number {
    return this.db.tx(() => {
      this.db.run('DELETE FROM indicators WHERE source = ?', source);
      return this.insertIndicators(source, rows);
    });
  }

  insertIndicators(source: string, rows: Iterable<IndicatorRow>): number {
    const stmt = this.db.raw.prepare(
      'INSERT OR REPLACE INTO indicators (source, type, value, first_seen, last_seen, threat, family, tags, confidence, reference, external_id, extra) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
    );
    let n = 0;
    for (const r of rows) {
      stmt.run(source, r.type, r.value, r.firstSeen ?? null, r.lastSeen ?? null, r.threat ?? null, r.family ?? null, r.tags ?? null, r.confidence ?? null, r.reference ?? null, r.externalId ?? null, r.extra ?? null);
      n++;
    }
    return n;
  }

  replaceCidrs(source: string, rows: { start: number; end: number; cidr: string; label: string | null; reference: string | null }[]): number {
    return this.db.tx(() => {
      this.db.run('DELETE FROM cidr4 WHERE source = ?', source);
      const stmt = this.db.raw.prepare('INSERT INTO cidr4 (source, start, end, cidr, label, reference) VALUES (?, ?, ?, ?, ?, ?)');
      for (const r of rows) stmt.run(source, r.start, r.end, r.cidr, r.label, r.reference);
      return rows.length;
    });
  }

  upsertEvent(source: string, e: EventRow): void {
    this.db.tx(() => {
      this.db.run(
        'INSERT OR REPLACE INTO events (source, id, name, date, updated_at, org, tags, threat_level, reference, attribute_count) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
        source,
        e.id,
        e.name,
        e.date,
        e.updatedAt,
        e.org,
        JSON.stringify(e.tags),
        e.threatLevel,
        e.reference,
        e.indicators.length,
      );
      this.db.run('DELETE FROM event_indicators WHERE source = ? AND event_id = ?', source, e.id);
      const stmt = this.db.raw.prepare('INSERT OR IGNORE INTO event_indicators (source, event_id, type, value, category, to_ids, comment) VALUES (?, ?, ?, ?, ?, ?, ?)');
      for (const i of e.indicators) stmt.run(source, e.id, i.type, i.value, i.category, i.toIds ? 1 : 0, i.comment ? i.comment.slice(0, 500) : null);
    });
  }

  /** Event header without touching its indicator list (online lookups add indicators one by one). */
  upsertEventHeader(source: string, e: Omit<EventRow, 'indicators'>): void {
    this.db.run(
      `INSERT INTO events (source, id, name, date, updated_at, org, tags, threat_level, reference, attribute_count) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
       ON CONFLICT(source, id) DO UPDATE SET name = excluded.name, date = excluded.date, updated_at = excluded.updated_at, org = excluded.org, tags = excluded.tags, reference = excluded.reference`,
      source,
      e.id,
      e.name,
      e.date,
      e.updatedAt,
      e.org,
      JSON.stringify(e.tags),
      e.threatLevel,
      e.reference,
    );
  }

  addEventIndicator(source: string, eventId: string, type: string, value: string): void {
    this.db.run('INSERT OR IGNORE INTO event_indicators (source, event_id, type, value, category, to_ids, comment) VALUES (?, ?, ?, ?, NULL, NULL, ?)', source, eventId, type, value, 'learned from online lookup');
    this.db.run('UPDATE events SET attribute_count = (SELECT COUNT(*) FROM event_indicators WHERE source = ? AND event_id = ?) WHERE source = ? AND id = ?', source, eventId, source, eventId);
  }

  eventTimestamps(source: string): Map<string, number | null> {
    return new Map(this.db.all<{ id: string; updated_at: number | null }>('SELECT id, updated_at FROM events WHERE source = ?', source).map((r) => [r.id, r.updated_at]));
  }

  removeEvents(source: string, ids: string[]): void {
    this.db.tx(() => {
      for (const id of ids) {
        this.db.run('DELETE FROM event_indicators WHERE source = ? AND event_id = ?', source, id);
        this.db.run('DELETE FROM events WHERE source = ? AND id = ?', source, id);
      }
    });
  }

  replacePopular(rows: Iterable<[string, number]>): number {
    return this.db.tx(() => {
      this.db.run('DELETE FROM popular');
      const stmt = this.db.raw.prepare('INSERT OR IGNORE INTO popular (domain, rank) VALUES (?, ?)');
      let n = 0;
      for (const [d, r] of rows) {
        stmt.run(d, r);
        n++;
      }
      return n;
    });
  }

  replaceAsn(v4: Iterable<[number, number, number, string]>, v6: Iterable<[string, string, number, string]>): number {
    return this.db.tx(() => {
      this.db.run('DELETE FROM asn4');
      this.db.run('DELETE FROM asn6');
      const s4 = this.db.raw.prepare('INSERT INTO asn4 (start, end, asn, name) VALUES (?, ?, ?, ?)');
      const s6 = this.db.raw.prepare('INSERT INTO asn6 (start, end, asn, name) VALUES (?, ?, ?, ?)');
      let n = 0;
      for (const r of v4) {
        s4.run(...r);
        n++;
      }
      for (const r of v6) {
        s6.run(...r);
        n++;
      }
      return n;
    });
  }

  cacheLookup(source: string, type: string, value: string, status: string, result: unknown, ttlMs: number): void {
    const now = Date.now();
    this.db.run(
      'INSERT OR REPLACE INTO lookups (source, type, value, fetched_at, expires_at, status, result_json) VALUES (?, ?, ?, ?, ?, ?, ?)',
      source,
      type,
      value,
      now,
      now + ttlMs,
      status,
      JSON.stringify(result),
    );
  }

  cachedLookup(source: string, type: string, value: string): { fetchedAt: number; status: string; result: unknown } | null {
    const r = this.db.get<{ fetched_at: number; expires_at: number; status: string; result_json: string }>('SELECT * FROM lookups WHERE source = ? AND type = ? AND value = ?', source, type, value);
    if (!r || r.expires_at < Date.now()) return null;
    return { fetchedAt: r.fetched_at, status: r.status, result: JSON.parse(r.result_json) as unknown };
  }

  logSync(row: { source: string; startedAt: number; finishedAt: number; status: string; records: number | null; events: number | null; bytes: number | null; sha256: string | null; error: string | null }): void {
    this.db.run(
      'INSERT INTO sync_log (source, started_at, finished_at, status, records, events, bytes, snapshot_sha256, error) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
      row.source,
      row.startedAt,
      row.finishedAt,
      row.status,
      row.records,
      row.events,
      row.bytes,
      row.sha256,
      row.error,
    );
  }

  recentSyncs(source: string, limit = 10): { started_at: number; finished_at: number | null; status: string; records: number | null; events: number | null; bytes: number | null; snapshot_sha256: string | null; error: string | null }[] {
    return this.db.all('SELECT started_at, finished_at, status, records, events, bytes, snapshot_sha256, error FROM sync_log WHERE source = ? ORDER BY started_at DESC LIMIT ?', source, limit);
  }
}

/** Fixed-width hex for lexicographic IPv6 range comparisons. */
export function ipv6Hex(ip: string): string | null {
  const parts = ip.split('::');
  if (parts.length > 2) return null;
  const head = parts[0] ? parts[0].split(':') : [];
  const tail = parts.length === 2 && parts[1] ? parts[1].split(':') : [];
  const missing = 8 - head.length - tail.length;
  if (missing < 0 || (parts.length === 1 && missing !== 0)) return null;
  const all = [...head, ...new Array<string>(parts.length === 2 ? missing : 0).fill('0'), ...tail];
  if (all.length !== 8 || all.some((h) => !/^[0-9a-f]{1,4}$/i.test(h))) return null;
  return all.map((h) => h.padStart(4, '0').toLowerCase()).join('');
}
