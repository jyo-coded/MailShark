// Everything a route handler needs, created once at start-up (see main.ts / createContext()).
import { join } from 'node:path';
import type { Config } from './config';
import { Db } from './db/sqlite';
import { CASE_MIGRATIONS } from './db/schema';
import { BlobStore } from './evidence/store';
import { JobQueue } from './jobs/queue';
import { WorkerPool } from './jobs/pool';
import { Processor } from './analysis/processor';
import { IntelService } from './intel/service';
import { Auth } from './security/auth';
import { Audit } from './security/audit';

export const PLATFORM_VERSION = '1.0.0';

export interface AppContext {
  cfg: Config;
  db: Db;
  caseDbPath: string;
  store: BlobStore;
  queue: JobQueue;
  pool: WorkerPool;
  processor: Processor;
  intel: IntelService;
  auth: Auth;
  audit: Audit;
  startedAt: number;
  setupToken: string | null;
  webRoot: string | null;
  log: (level: 'info' | 'warn' | 'error', msg: string) => void;
}

export interface ContextOptions {
  workerScript: string;
  intelWorkerScript: string | null;
  webRoot: string | null;
  log?: AppContext['log'];
}

export function createContext(cfg: Config, opts: ContextOptions): AppContext {
  const log = opts.log ?? ((level, msg) => (level === 'info' ? console.log(msg) : console.error(msg)));
  const caseDbPath = join(cfg.dataDir, 'case.db');
  const db = new Db(caseDbPath);
  db.migrate(CASE_MIGRATIONS);
  const store = new BlobStore(cfg.dataDir);
  const queue = new JobQueue(db);
  const pool = new WorkerPool(opts.workerScript, cfg.workers, cfg.workerHeapMb, (m) => log('warn', `[pool] ${m}`));
  const intelDbPath = join(cfg.dataDir, 'intel.db');
  const intel = new IntelService(cfg, intelDbPath, opts.intelWorkerScript, (level, msg) => log(level, msg));
  const processor = new Processor({ cfg, db, queue, pool, intelDbPath, caseDbPath, log });
  const auth = new Auth(db, cfg.session);
  const audit = new Audit(db);
  return { cfg, db, caseDbPath, store, queue, pool, processor, intel, auth, audit, startedAt: Date.now(), setupToken: null, webRoot: opts.webRoot, log };
}

export async function closeContext(ctx: AppContext): Promise<void> {
  await ctx.processor.stop();
  await ctx.pool.close();
  await ctx.intel.stop();
  ctx.db.close();
}
