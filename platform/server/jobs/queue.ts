// Persistent job queue in case.db. Jobs survive restarts: anything "running" when the process
// stopped is put back in the queue (or failed once it has used all its attempts).
import type { Db } from '../db/sqlite';

export type JobKind = 'expand' | 'analyze' | 'correlate';

export interface Job {
  id: number;
  kind: JobKind;
  case_id: string | null;
  ref: string;
  status: 'queued' | 'running' | 'done' | 'failed' | 'cancelled';
  priority: number;
  attempts: number;
  max_attempts: number;
  run_after: number;
  leased_until: number | null;
  last_error: string | null;
}

export class JobQueue {
  constructor(private readonly db: Db) {}

  /** Adds a job unless an identical one (same kind and ref) is already waiting or running. */
  enqueue(kind: JobKind, caseId: string | null, ref: string, opts: { priority?: number; maxAttempts?: number; delayMs?: number } = {}): number {
    const existing = this.db.get<{ id: number; status: string }>("SELECT id, status FROM jobs WHERE kind = ? AND ref = ? AND status IN ('queued', 'running') ORDER BY id DESC LIMIT 1", kind, ref);
    const now = Date.now();
    if (existing) {
      // A correlation requested while one is running must run again afterwards with the new data.
      if (existing.status === 'running' && kind === 'correlate') {
        const pending = this.db.get<{ id: number }>("SELECT id FROM jobs WHERE kind = ? AND ref = ? AND status = 'queued'", kind, ref);
        if (pending) return pending.id;
      } else return existing.id;
    }
    return this.db.run(
      'INSERT INTO jobs (kind, case_id, ref, status, priority, attempts, max_attempts, run_after, created_at, updated_at) VALUES (?, ?, ?, ?, ?, 0, ?, ?, ?, ?)',
      kind,
      caseId,
      ref,
      'queued',
      opts.priority ?? 5,
      opts.maxAttempts ?? 3,
      now + (opts.delayMs ?? 0),
      now,
      now,
    ).lastInsertRowid;
  }

  /** Claims up to `limit` runnable jobs and marks them running (single-writer, so this is atomic). */
  claim(limit: number, leaseMs: number, kinds?: JobKind[]): Job[] {
    if (limit <= 0) return [];
    const now = Date.now();
    const kindFilter = kinds?.length ? `AND kind IN (${kinds.map(() => '?').join(',')})` : '';
    return this.db.tx(() => {
      const rows = this.db.all<Job>(`SELECT * FROM jobs WHERE status = 'queued' AND run_after <= ? ${kindFilter} ORDER BY priority, id LIMIT ?`, now, ...(kinds ?? []), limit);
      for (const r of rows) {
        this.db.run("UPDATE jobs SET status = 'running', attempts = attempts + 1, leased_until = ?, updated_at = ? WHERE id = ?", now + leaseMs, now, r.id);
        r.attempts += 1;
        r.status = 'running';
      }
      return rows;
    });
  }

  complete(id: number): void {
    this.db.run("UPDATE jobs SET status = 'done', leased_until = NULL, last_error = NULL, updated_at = ? WHERE id = ?", Date.now(), id);
  }

  /** Records a failure. Retryable failures go back to the queue with exponential backoff until attempts run out. */
  fail(job: Job, error: string, retryable: boolean): 'retry' | 'failed' {
    const now = Date.now();
    if (retryable && job.attempts < job.max_attempts) {
      const delay = Math.min(5 * 60_000, 2000 * 4 ** (job.attempts - 1));
      this.db.run("UPDATE jobs SET status = 'queued', run_after = ?, leased_until = NULL, last_error = ?, updated_at = ? WHERE id = ?", now + delay, error.slice(0, 1000), now, job.id);
      return 'retry';
    }
    this.db.run("UPDATE jobs SET status = 'failed', leased_until = NULL, last_error = ?, updated_at = ? WHERE id = ?", error.slice(0, 1000), now, job.id);
    return 'failed';
  }

  /** Start-up recovery: jobs left "running" by a crash or restart. */
  recover(): { requeued: Job[]; failed: Job[] } {
    const now = Date.now();
    const stuck = this.db.all<Job>("SELECT * FROM jobs WHERE status = 'running'");
    const requeued: Job[] = [];
    const failed: Job[] = [];
    for (const j of stuck) {
      if (j.attempts < j.max_attempts) {
        this.db.run("UPDATE jobs SET status = 'queued', run_after = ?, leased_until = NULL, last_error = 'interrupted (server stopped while running)', updated_at = ? WHERE id = ?", now, now, j.id);
        requeued.push(j);
      } else {
        this.db.run("UPDATE jobs SET status = 'failed', leased_until = NULL, last_error = 'interrupted repeatedly; giving up', updated_at = ? WHERE id = ?", now, j.id);
        failed.push(j);
      }
    }
    return { requeued, failed };
  }

  cancelForCase(caseId: string): void {
    this.db.run("UPDATE jobs SET status = 'cancelled', updated_at = ? WHERE case_id = ? AND status IN ('queued', 'running')", Date.now(), caseId);
  }

  depth(): { queued: number; running: number; failed24h: number } {
    const r = this.db.get<{ queued: number; running: number; failed24h: number }>(
      "SELECT SUM(status = 'queued') AS queued, SUM(status = 'running') AS running, SUM(status = 'failed' AND updated_at > ?) AS failed24h FROM jobs",
      Date.now() - 86_400_000,
    );
    return { queued: r?.queued ?? 0, running: r?.running ?? 0, failed24h: r?.failed24h ?? 0 };
  }

  get(id: number): Job | undefined {
    return this.db.get<Job>('SELECT * FROM jobs WHERE id = ?', id);
  }
}
