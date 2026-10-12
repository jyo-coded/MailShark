// worker_threads pool with per-task timeouts and heap limits. A task that hangs is terminated and
// its worker replaced; a worker that runs out of memory is replaced. Failures are classified so the
// queue can retry transient problems and fail deterministic ones immediately.
import { Worker } from 'node:worker_threads';
import type { WorkerTask } from './worker';

export class TaskError extends Error {
  constructor(
    readonly code: string,
    message: string,
    readonly retryable: boolean,
  ) {
    super(message);
  }
}

// Errors that will happen again with the same input: retrying wastes time.
const DETERMINISTIC = new Set(['unsupported-format', 'empty-file', 'binary-not-email', 'ole-not-msg', 'malformed-container', 'unsupported-encoding', 'msg-parse-error', 'integrity-error', 'ENOENT']);

interface Slot {
  worker: Worker;
  busy: boolean;
  current: { taskId: number; resolve: (v: unknown) => void; reject: (e: unknown) => void; timer: NodeJS.Timeout } | null;
}

export class WorkerPool {
  private slots: Slot[] = [];
  private waiting: { task: WorkerTask; timeoutMs: number; resolve: (v: unknown) => void; reject: (e: unknown) => void }[] = [];
  private nextId = 0;
  private closed = false;

  constructor(
    private readonly script: string,
    readonly size: number,
    private readonly heapMb: number,
    private readonly log: (msg: string) => void = () => undefined,
  ) {
    for (let i = 0; i < size; i++) this.slots.push(this.spawn());
  }

  private spawn(): Slot {
    const worker = new Worker(this.script, { resourceLimits: { maxOldGenerationSizeMb: this.heapMb, maxYoungGenerationSizeMb: 64 } });
    const slot: Slot = { worker, busy: false, current: null };
    worker.on('message', (m: { taskId: number; ok: boolean; result?: unknown; error?: { code: string; message: string } }) => {
      const cur = slot.current;
      if (!cur || cur.taskId !== m.taskId) return;
      clearTimeout(cur.timer);
      slot.current = null;
      slot.busy = false;
      if (m.ok) cur.resolve(m.result);
      else {
        const code = m.error?.code ?? 'error';
        cur.reject(new TaskError(code, m.error?.message ?? 'task failed', !DETERMINISTIC.has(code)));
      }
      this.pump();
    });
    const onDeath = (err: Error | null, exitCode?: number): void => {
      const cur = slot.current;
      slot.current = null;
      slot.busy = false;
      if (cur) {
        clearTimeout(cur.timer);
        const oom = (err as { code?: string } | null)?.code === 'ERR_WORKER_OUT_OF_MEMORY';
        cur.reject(new TaskError(oom ? 'resource-limit' : 'worker-crash', oom ? `analysis exceeded the ${this.heapMb} MB memory limit` : `worker stopped unexpectedly${err ? `: ${err.message}` : exitCode !== undefined ? ` (exit ${exitCode})` : ''}`, true));
      }
      if (this.closed) return;
      const idx = this.slots.indexOf(slot);
      if (idx >= 0) {
        this.slots[idx] = this.spawn();
        this.pump();
      }
    };
    worker.on('error', (e) => {
      this.log(`worker error: ${e.message}`);
      onDeath(e);
    });
    worker.on('exit', (code) => {
      if (slot.worker === worker && (slot.busy || !this.closed)) onDeath(null, code);
    });
    return slot;
  }

  run<T>(task: WorkerTask, timeoutMs: number): Promise<T> {
    if (this.closed) return Promise.reject(new TaskError('shutdown', 'pool is closed', true));
    return new Promise<T>((resolve, reject) => {
      this.waiting.push({ task, timeoutMs, resolve: resolve as (v: unknown) => void, reject });
      this.pump();
    });
  }

  private pump(): void {
    for (const slot of this.slots) {
      if (slot.busy || !this.waiting.length) continue;
      const job = this.waiting.shift() as (typeof this.waiting)[number];
      const taskId = ++this.nextId;
      slot.busy = true;
      const timer = setTimeout(() => {
        if (slot.current?.taskId !== taskId) return;
        const cur = slot.current;
        slot.current = null;
        slot.busy = false;
        cur.reject(new TaskError('timeout', `task exceeded ${Math.round(job.timeoutMs / 1000)} s and was stopped`, true));
        // Replace the worker: the stuck task may still be running inside it.
        const idx = this.slots.indexOf(slot);
        void slot.worker.terminate();
        if (idx >= 0 && !this.closed) this.slots[idx] = this.spawn();
        this.pump();
      }, job.timeoutMs);
      slot.current = { taskId, resolve: job.resolve, reject: job.reject, timer };
      slot.worker.postMessage({ taskId, task: job.task });
    }
  }

  stats(): { size: number; busy: number; queued: number } {
    return { size: this.slots.length, busy: this.slots.filter((s) => s.busy).length, queued: this.waiting.length };
  }

  idle(): number {
    return this.slots.filter((s) => !s.busy).length - this.waiting.length;
  }

  async close(): Promise<void> {
    this.closed = true;
    for (const w of this.waiting) w.reject(new TaskError('shutdown', 'server is shutting down', true));
    this.waiting = [];
    await Promise.all(this.slots.map((s) => s.worker.terminate()));
  }
}
