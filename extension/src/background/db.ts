// Local evidence store (IndexedDB). Everything MailShark learns stays in this database.
import { openDB, type DBSchema, type IDBPDatabase } from 'idb';
import type { Fingerprint, Verdict } from '../../../engine/src/types';
import type { CampaignRecord, StoredReport } from '../shared/protocol';

export interface MemberRow {
  id: string;
  clusterId: string | null;
  fp: Fingerprint;
  score: number;
  verdict: Verdict;
  time: number;
}

export interface KeyRow {
  key: string;
  ids: string[];
}

export interface SenderRow {
  address: string;
  count: number;
  firstSeen: number;
  lastSeen: number;
}

export interface FeedRow {
  name: string;
  m: number;
  k: number;
  count: number;
  updated: string | null;
  sha256: string;
  bits: ArrayBuffer;
}

interface MailSharkDB extends DBSchema {
  reports: { key: string; value: StoredReport; indexes: { storedAt: number; messageId: string; clusterId: string } };
  members: { key: string; value: MemberRow; indexes: { time: number; clusterId: string } };
  keys: { key: string; value: KeyRow };
  campaigns: { key: string; value: CampaignRecord; indexes: { updatedAt: number } };
  senders: { key: string; value: SenderRow };
  feeds: { key: string; value: FeedRow };
  kv: { key: string; value: { k: string; v: unknown } };
}

export type DB = IDBPDatabase<MailSharkDB>;
export const MAX_KEY_FANOUT = 250;
export const MAX_REPORTS = 4000;

let dbPromise: Promise<DB> | null = null;

export function db(): Promise<DB> {
  dbPromise ??= openDB<MailSharkDB>('mailshark', 1, {
    upgrade(d) {
      const reports = d.createObjectStore('reports', { keyPath: 'id' });
      reports.createIndex('storedAt', 'meta.storedAt');
      reports.createIndex('messageId', 'meta.messageId');
      reports.createIndex('clusterId', 'meta.clusterId');
      const members = d.createObjectStore('members', { keyPath: 'id' });
      members.createIndex('time', 'time');
      members.createIndex('clusterId', 'clusterId');
      d.createObjectStore('keys', { keyPath: 'key' });
      const campaigns = d.createObjectStore('campaigns', { keyPath: 'id' });
      campaigns.createIndex('updatedAt', 'updatedAt');
      d.createObjectStore('senders', { keyPath: 'address' });
      d.createObjectStore('feeds', { keyPath: 'name' });
      d.createObjectStore('kv', { keyPath: 'k' });
    },
    blocking() {
      dbPromise = null;
    },
  });
  return dbPromise;
}

export async function kvGet<T>(k: string): Promise<T | undefined> {
  const row = await (await db()).get('kv', k);
  return row?.v as T | undefined;
}

export async function kvSet(k: string, v: unknown): Promise<void> {
  await (await db()).put('kv', { k, v });
}

/** Drop the oldest safe reports beyond MAX_REPORTS (threat evidence is kept longest). */
export async function prune(): Promise<number> {
  const d = await db();
  const total = await d.count('reports');
  if (total <= MAX_REPORTS) return 0;
  let excess = total - MAX_REPORTS;
  let removed = 0;
  const tx = d.transaction(['reports', 'members'], 'readwrite');
  const passes: Verdict[] = ['safe', 'caution', 'danger'];
  for (const pass of passes) {
    let cursor = await tx.objectStore('reports').index('storedAt').openCursor();
    while (cursor && excess > 0) {
      if (cursor.value.report.verdict === pass) {
        await tx.objectStore('members').delete(cursor.value.id);
        await cursor.delete();
        excess--;
        removed++;
      }
      cursor = await cursor.continue();
    }
    if (excess <= 0) break;
  }
  await tx.done;
  return removed;
}

export async function wipe(): Promise<void> {
  const d = await db();
  const tx = d.transaction(['reports', 'members', 'keys', 'campaigns', 'senders', 'kv'], 'readwrite');
  await Promise.all([
    tx.objectStore('reports').clear(),
    tx.objectStore('members').clear(),
    tx.objectStore('keys').clear(),
    tx.objectStore('campaigns').clear(),
    tx.objectStore('senders').clear(),
    tx.objectStore('kv').clear(),
    tx.done,
  ]);
}
