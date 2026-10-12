// Runs one connector's sync and records the outcome (status, counts, snapshot hash, next due time).
// A failed sync keeps the previous data: the source becomes "stale", never silently empty.
import type { IntelConfig } from '../config';
import { missingRequirements, type Connector } from './sources';
import type { IntelStore } from './store';

export interface SyncReport {
  source: string;
  status: 'updated' | 'not-modified' | 'partial' | 'error' | 'not-configured';
  records: number | null;
  durationMs: number;
  error: string | null;
  notes: string[];
}

export async function runSync(store: IntelStore, c: Connector, cfg: IntelConfig, log: (m: string) => void = () => undefined): Promise<SyncReport> {
  const started = Date.now();
  if (!c.sync) return { source: c.id, status: 'error', records: null, durationMs: 0, error: 'not a downloadable source', notes: [] };
  const missing = missingRequirements(c, cfg);
  if (missing.length) {
    store.updateSource(c.id, { last_attempt: started, last_error: `Not configured: set ${missing.join(', ')}`, next_due: started + 24 * 3600_000 });
    return { source: c.id, status: 'not-configured', records: null, durationMs: 0, error: `requires ${missing.join(', ')}`, notes: [] };
  }
  const row = store.sourceRow(c.id);
  store.updateSource(c.id, { last_attempt: started });
  let state: Record<string, unknown> = {};
  try {
    state = row?.state_json ? (JSON.parse(row.state_json) as Record<string, unknown>) : {};
  } catch {
    state = {};
  }
  try {
    const out = await c.sync({ store, config: cfg, etag: row?.etag ?? null, lastModified: row?.last_modified ?? null, state, log });
    const finished = Date.now();
    const intervalMs = c.intervalHours * 3600_000;
    store.updateSource(c.id, {
      last_success: finished,
      last_error: null,
      etag: out.etag ?? row?.etag ?? null,
      last_modified: out.lastModified ?? row?.last_modified ?? null,
      next_due: finished + (out.status === 'partial' ? 10 * 60_000 : intervalMs),
      ...(out.status !== 'not-modified' ? { record_count: out.records, snapshot_sha256: out.sha256 ?? row?.snapshot_sha256 ?? null } : {}),
      ...(out.events !== undefined ? { event_count: out.events } : {}),
      ...(out.state ? { state_json: JSON.stringify(out.state) } : {}),
    });
    store.logSync({ source: c.id, startedAt: started, finishedAt: finished, status: out.status, records: out.records >= 0 ? out.records : null, events: out.events ?? null, bytes: out.bytes, sha256: out.sha256, error: null });
    log(`[intel] ${c.id}: ${out.status}${out.records >= 0 ? `, ${out.records} records` : ''}${out.notes?.length ? ` (${out.notes.join('; ')})` : ''}`);
    return { source: c.id, status: out.status, records: out.records >= 0 ? out.records : null, durationMs: finished - started, error: null, notes: out.notes ?? [] };
  } catch (e) {
    const finished = Date.now();
    const msg = e instanceof Error ? e.message : String(e);
    // Retry sooner than the normal interval, but never hammer an unavailable provider.
    store.updateSource(c.id, { last_error: msg.slice(0, 500), next_due: finished + Math.min(Math.max(c.intervalHours, 1), 6) * 3600_000 });
    store.logSync({ source: c.id, startedAt: started, finishedAt: finished, status: 'error', records: null, events: null, bytes: null, sha256: null, error: msg.slice(0, 500) });
    log(`[intel] ${c.id}: error: ${msg}`);
    return { source: c.id, status: 'error', records: null, durationMs: finished - started, error: msg, notes: [] };
  }
}
