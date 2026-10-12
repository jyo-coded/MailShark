// Intelligence service (main thread): schedules feed syncs in the intel worker, reports source
// freshness honestly, and performs opt-in online lookups with caching and rate limits.
import { Worker } from 'node:worker_threads';
import type { Config } from '../config';
import { CONNECTORS, connector, missingRequirements, type Connector, type LookupResult } from './sources';
import { IntelStore, type SourceStatusRow } from './store';
import type { SyncReport } from './sync';
import type { IntelType } from './normalize';

export type Freshness = 'current' | 'stale' | 'never-synced' | 'unavailable' | 'not-configured' | 'disabled' | 'syncing' | 'available';

export interface SourceInfo {
  id: string;
  name: string;
  provider: string;
  kind: Connector['kind'];
  attribution: Connector['attribution'];
  access: Connector['access'];
  homepage: string;
  license: string;
  provides: string;
  intervalHours: number;
  enabled: boolean;
  freshness: Freshness;
  missing: string[];
  recordCount: number;
  eventCount: number;
  lastSuccess: number | null;
  lastAttempt: number | null;
  lastError: string | null;
  nextDue: number | null;
  snapshotSha256: string | null;
  lookupTypes: IntelType[];
}

export interface LookupOutcome extends LookupResult {
  source: string;
  cached: boolean;
  fetchedAt: number;
}

export class IntelService {
  readonly store: IntelStore;
  private worker: Worker | null = null;
  private timer: NodeJS.Timeout | null = null;
  private running = new Set<string>();
  private queue: string[] = [];
  private busy = false;
  private requestId = 0;
  private waiters = new Map<number, (r: SyncReport[]) => void>();

  constructor(
    private readonly cfg: Config,
    readonly dbPath: string,
    private readonly workerScript: string | null,
    private readonly log: (level: 'info' | 'warn', msg: string) => void,
  ) {
    this.store = new IntelStore(dbPath);
    for (const c of CONNECTORS) this.store.ensureSource(c.id, c.defaultEnabled);
  }

  start(): void {
    if (!this.cfg.intel.autoSync || !this.workerScript) return;
    const tick = (): void => {
      const due = this.dueSources();
      if (due.length) this.enqueue(due);
    };
    setTimeout(tick, 5_000).unref();
    this.timer = setInterval(tick, 60_000);
    this.timer.unref();
  }

  async stop(): Promise<void> {
    if (this.timer) clearInterval(this.timer);
    if (this.worker) await this.worker.terminate();
    this.worker = null;
    this.store.close();
  }

  private dueSources(): string[] {
    const now = Date.now();
    const rows = new Map(this.store.sourceStatus().map((r) => [r.id, r]));
    // Enrichment first: the popularity list is needed to filter domain feeds.
    return CONNECTORS.filter((c) => c.sync && c.kind !== 'lookup')
      .sort((a, b) => (a.kind === 'enrichment' ? 0 : 1) - (b.kind === 'enrichment' ? 0 : 1))
      .filter((c) => {
        const r = rows.get(c.id);
        if (!r || !r.enabled || this.running.has(c.id) || this.queue.includes(c.id)) return false;
        if (missingRequirements(c, this.cfg.intel).length) return false;
        return r.next_due === null || r.next_due <= now;
      })
      .map((c) => c.id);
  }

  private ensureWorker(): Worker {
    if (this.worker) return this.worker;
    if (!this.workerScript) throw new Error('intel worker unavailable');
    const w = new Worker(this.workerScript, { resourceLimits: { maxOldGenerationSizeMb: 3072 } });
    w.on('message', (m: { type: string; requestId?: number; source?: string; state?: string; message?: string; reports?: SyncReport[]; error?: string }) => {
      if (m.type === 'log' && m.message) this.log('info', m.message);
      if (m.type === 'progress' && m.source) {
        if (m.state === 'running') this.running.add(m.source);
        else this.running.delete(m.source);
      }
      if ((m.type === 'done' || m.type === 'error') && m.requestId !== undefined) {
        if (m.type === 'error') this.log('warn', `[intel] worker error: ${m.error}`);
        this.waiters.get(m.requestId)?.(m.reports ?? []);
        this.waiters.delete(m.requestId);
      }
    });
    w.on('error', (e) => this.log('warn', `[intel] worker crashed: ${e.message}`));
    w.on('exit', () => {
      this.worker = null;
      this.running.clear();
      for (const [, resolve] of this.waiters) resolve([]);
      this.waiters.clear();
      this.busy = false;
    });
    this.worker = w;
    return w;
  }

  /** Queue sources for sync; resolves when they have been processed. */
  enqueue(ids: string[]): Promise<SyncReport[]> {
    for (const id of ids) if (!this.queue.includes(id) && !this.running.has(id)) this.queue.push(id);
    return this.drain();
  }

  private drain(): Promise<SyncReport[]> {
    if (this.busy || !this.queue.length) return Promise.resolve([]);
    this.busy = true;
    const ids = this.queue.splice(0, this.queue.length);
    const requestId = ++this.requestId;
    return new Promise<SyncReport[]>((resolve) => {
      this.waiters.set(requestId, (reports) => {
        this.busy = false;
        resolve(reports);
        void this.drain();
      });
      try {
        this.ensureWorker().postMessage({ type: 'sync', requestId, dbPath: this.dbPath, ids, config: this.cfg.intel });
      } catch (e) {
        this.busy = false;
        this.waiters.delete(requestId);
        this.log('warn', `[intel] cannot start sync: ${e instanceof Error ? e.message : String(e)}`);
        resolve([]);
      }
    });
  }

  isSyncing(id: string): boolean {
    return this.running.has(id) || this.queue.includes(id);
  }

  setEnabled(id: string, enabled: boolean): void {
    if (!connector(id)) throw new Error('unknown source');
    this.store.setEnabled(id, enabled);
  }

  sources(): SourceInfo[] {
    const rows = new Map(this.store.sourceStatus().map((r) => [r.id, r]));
    return CONNECTORS.map((c) => this.info(c, rows.get(c.id)));
  }

  private info(c: Connector, r: SourceStatusRow | undefined): SourceInfo {
    const missing = missingRequirements(c, this.cfg.intel);
    const enabled = !!r?.enabled;
    let freshness: Freshness;
    if (!enabled) freshness = 'disabled';
    else if (missing.length) freshness = 'not-configured';
    else if (c.kind === 'lookup') freshness = this.cfg.allowOnlineLookups ? 'available' : 'disabled';
    else if (this.isSyncing(c.id)) freshness = 'syncing';
    else if (!r?.last_success) freshness = r?.last_error ? 'unavailable' : 'never-synced';
    else if (Date.now() - r.last_success > Math.max(3 * c.intervalHours * 3600_000, 48 * 3600_000) || (r.last_error && (r.last_attempt ?? 0) > r.last_success)) freshness = 'stale';
    else freshness = 'current';
    return {
      id: c.id,
      name: c.name,
      provider: c.provider,
      kind: c.kind,
      attribution: c.attribution,
      access: c.access,
      homepage: c.homepage,
      license: c.license,
      provides: c.provides,
      intervalHours: c.intervalHours,
      enabled,
      freshness,
      missing,
      recordCount: r?.record_count ?? 0,
      eventCount: r?.event_count ?? 0,
      lastSuccess: r?.last_success ?? null,
      lastAttempt: r?.last_attempt ?? null,
      lastError: r?.last_error ?? null,
      nextDue: r?.next_due ?? null,
      snapshotSha256: r?.snapshot_sha256 ?? null,
      lookupTypes: c.lookupTypes ?? [],
    };
  }

  /** Online lookups for one indicator across the enabled, configured lookup sources. */
  async lookup(type: IntelType, value: string, only?: string[]): Promise<LookupOutcome[]> {
    if (!this.cfg.allowOnlineLookups) return [];
    const rows = new Map(this.store.sourceStatus().map((r) => [r.id, r]));
    const out: LookupOutcome[] = [];
    for (const c of CONNECTORS) {
      if (c.kind !== 'lookup' || !c.lookup || !(c.lookupTypes ?? []).includes(type)) continue;
      if (only && !only.includes(c.id)) continue;
      if (!rows.get(c.id)?.enabled || missingRequirements(c, this.cfg.intel).length) continue;
      const cached = this.store.cachedLookup(c.id, type, value);
      if (cached) {
        out.push({ ...(cached.result as LookupResult), source: c.id, cached: true, fetchedAt: cached.fetchedAt });
        continue;
      }
      let res: LookupResult;
      try {
        res = await c.lookup({ store: this.store, config: this.cfg.intel }, type, value);
      } catch (e) {
        res = { status: 'error', hits: [], events: [], detail: e instanceof Error ? e.message : String(e) };
      }
      const fetchedAt = Date.now();
      if (res.status !== 'error') this.store.cacheLookup(c.id, type, value, res.status, res, res.status === 'found' ? 24 * 3600_000 : 6 * 3600_000);
      // Campaign records learned online are kept, linked to the looked-up value, for offline correlation.
      for (const ev of res.events) {
        this.store.upsertEventHeader(c.id, ev);
        this.store.addEventIndicator(c.id, ev.id, type, value);
      }
      for (const h of res.hits) this.store.db.run('INSERT OR REPLACE INTO indicators (source, type, value, first_seen, last_seen, threat, family, tags, confidence, reference, external_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', c.id, type, value, h.firstSeen, h.lastSeen, h.threat, h.family, h.tags, h.confidence, h.reference, h.externalId);
      out.push({ ...res, source: c.id, cached: false, fetchedAt });
    }
    return out;
  }
}
