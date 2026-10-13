// Append-only, hash-chained audit log. Each entry's hash covers its content and the previous
// entry's hash, so any edit or deletion breaks the chain from that point on (database triggers also
// refuse UPDATE/DELETE). verify() recomputes the whole chain.
import { createHash } from 'node:crypto';
import type { Db } from '../db/sqlite';

export interface AuditInput {
  userId?: string | null;
  username?: string | null;
  action: string;
  caseId?: string | null;
  target?: string | null;
  details?: unknown;
  ip?: string | null;
}

export interface AuditEntry {
  seq: number;
  ts: number;
  user_id: string | null;
  username: string | null;
  action: string;
  case_id: string | null;
  target: string | null;
  details: string | null;
  ip: string | null;
  prev_hash: string;
  hash: string;
}

const GENESIS = '0'.repeat(64);

function entryHash(prev: string, e: Omit<AuditEntry, 'seq' | 'prev_hash' | 'hash'>): string {
  const canonical = JSON.stringify([e.ts, e.user_id, e.username, e.action, e.case_id, e.target, e.details, e.ip]);
  return createHash('sha256').update(prev).update('\n').update(canonical).digest('hex');
}

export class Audit {
  constructor(private readonly db: Db) {}

  record(a: AuditInput): void {
    this.db.tx(() => {
      const prev = this.db.get<{ hash: string }>('SELECT hash FROM audit ORDER BY seq DESC LIMIT 1')?.hash ?? GENESIS;
      const e = {
        ts: Date.now(),
        user_id: a.userId ?? null,
        username: a.username ?? null,
        action: a.action,
        case_id: a.caseId ?? null,
        target: a.target ?? null,
        details: a.details === undefined ? null : JSON.stringify(a.details),
        ip: a.ip ?? null,
      };
      this.db.run(
        'INSERT INTO audit (ts, user_id, username, action, case_id, target, details, ip, prev_hash, hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
        e.ts,
        e.user_id,
        e.username,
        e.action,
        e.case_id,
        e.target,
        e.details,
        e.ip,
        prev,
        entryHash(prev, e),
      );
    });
  }

  list(opts: { caseId?: string | null; limit?: number; before?: number | null } = {}): AuditEntry[] {
    const limit = Math.min(Math.max(opts.limit ?? 100, 1), 1000);
    if (opts.caseId) return this.db.all<AuditEntry>('SELECT * FROM audit WHERE case_id = ? AND seq < ? ORDER BY seq DESC LIMIT ?', opts.caseId, opts.before ?? Number.MAX_SAFE_INTEGER, limit);
    return this.db.all<AuditEntry>('SELECT * FROM audit WHERE seq < ? ORDER BY seq DESC LIMIT ?', opts.before ?? Number.MAX_SAFE_INTEGER, limit);
  }

  verify(): { ok: boolean; entries: number; brokenAt: number | null; head: string } {
    let prev = GENESIS;
    let n = 0;
    for (const e of this.db.raw.prepare('SELECT * FROM audit ORDER BY seq').iterate() as IterableIterator<AuditEntry>) {
      n++;
      if (e.prev_hash !== prev || entryHash(prev, e) !== e.hash) return { ok: false, entries: n, brokenAt: e.seq, head: prev };
      prev = e.hash;
    }
    return { ok: true, entries: n, brokenAt: null, head: prev };
  }
}
