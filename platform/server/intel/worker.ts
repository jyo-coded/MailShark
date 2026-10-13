// Dedicated worker thread for intelligence downloads: parsing a 60 MB feed must never block the API.
import { parentPort } from 'node:worker_threads';
import type { IntelConfig } from '../config';
import { connector } from './sources';
import { IntelStore } from './store';
import { runSync, type SyncReport } from './sync';

interface SyncRequest {
  type: 'sync';
  requestId: number;
  dbPath: string;
  ids: string[];
  config: IntelConfig;
}

let store: IntelStore | null = null;

parentPort?.on('message', (msg: SyncRequest) => {
  void (async () => {
    if (msg.type !== 'sync') return;
    store ??= new IntelStore(msg.dbPath);
    const reports: SyncReport[] = [];
    for (const id of msg.ids) {
      const c = connector(id);
      if (!c) continue;
      parentPort?.postMessage({ type: 'progress', requestId: msg.requestId, source: id, state: 'running' });
      const r = await runSync(store, c, msg.config, (m) => parentPort?.postMessage({ type: 'log', message: m }));
      reports.push(r);
      parentPort?.postMessage({ type: 'progress', requestId: msg.requestId, source: id, state: r.status, report: r });
    }
    parentPort?.postMessage({ type: 'done', requestId: msg.requestId, reports });
  })().catch((e: unknown) => parentPort?.postMessage({ type: 'error', requestId: msg.requestId, error: e instanceof Error ? e.message : String(e) }));
});
