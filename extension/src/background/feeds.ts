// Threat-intelligence feeds. Public blocklists are compiled into Bloom filters by a GitHub Action
// (feeds/build_feeds.py) and published as static files. The extension downloads whole filters and
// checks domains locally: no domain from the user's mail is ever sent anywhere.
import { BloomFilter, BloomIntel } from '../../../engine/src/intel/bloom';
import type { FeedStatus } from '../shared/protocol';
import { db, kvGet, kvSet, type FeedRow } from './db';
import { loadSettings } from '../shared/settings';
import { FEED_BASE } from '../shared/constants';

const MAX_FILE_BYTES = 12 * 1024 * 1024;

interface FeedManifest {
  version: number;
  generated: string;
  lists: { name: string; file: string; m: number; k: number; count: number; sha256: string; updated: string | null }[];
}

let intel: BloomIntel | null = null;
let loaded = false;

async function sha256(buf: ArrayBuffer): Promise<string> {
  const d = await crypto.subtle.digest('SHA-256', buf);
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

function build(rows: FeedRow[]): BloomIntel | null {
  const filters: BloomFilter[] = [];
  for (const r of rows) {
    try {
      filters.push(new BloomFilter({ name: r.name, m: r.m, k: r.k, count: r.count }, new Uint8Array(r.bits)));
    } catch {
      /* corrupt row: ignored until next refresh */
    }
  }
  return filters.length ? new BloomIntel(filters) : null;
}

export async function getIntel(): Promise<BloomIntel | null> {
  const settings = await loadSettings();
  if (!settings.feeds) return null;
  if (!loaded) {
    intel = build(await (await db()).getAll('feeds'));
    loaded = true;
  }
  return intel;
}

export async function feedStatus(): Promise<FeedStatus> {
  const settings = await loadSettings();
  const rows = await (await db()).getAll('feeds');
  const meta = (await kvGet<{ lastCheck: number | null; lastSuccess: number | null; error: string | null }>('feedStatus')) ?? { lastCheck: null, lastSuccess: null, error: null };
  return {
    enabled: settings.feeds,
    entries: rows.reduce((n, r) => n + r.count, 0),
    lists: rows.map((r) => ({ name: r.name, count: r.count, updated: r.updated })),
    ...meta,
  };
}

export async function refreshFeeds(): Promise<FeedStatus> {
  const settings = await loadSettings();
  if (!settings.feeds) return feedStatus();
  const now = Date.now();
  let error: string | null = null;
  const prev = (await kvGet<{ lastSuccess: number | null }>('feedStatus')) ?? { lastSuccess: null };
  try {
    const res = await fetch(FEED_BASE + 'manifest.json', { cache: 'no-cache', credentials: 'omit' });
    if (!res.ok) throw new Error(`Feed manifest unavailable (HTTP ${res.status})`);
    const manifest = (await res.json()) as FeedManifest;
    if (manifest.version !== 1 || !Array.isArray(manifest.lists)) throw new Error('Unsupported feed manifest');
    const d = await db();
    const existing = new Map((await d.getAll('feeds')).map((r) => [r.name, r]));
    for (const list of manifest.lists) {
      if (!/^[a-z0-9._-]+$/i.test(list.file) || list.m <= 0 || list.k <= 0 || list.k > 32) continue;
      if (existing.get(list.name)?.sha256 === list.sha256) continue;
      const fr = await fetch(FEED_BASE + list.file, { cache: 'no-cache', credentials: 'omit' });
      if (!fr.ok) throw new Error(`Feed ${list.name} unavailable (HTTP ${fr.status})`);
      const buf = await fr.arrayBuffer();
      if (buf.byteLength > MAX_FILE_BYTES || buf.byteLength * 8 < list.m) throw new Error(`Feed ${list.name} has an unexpected size`);
      if ((await sha256(buf)) !== list.sha256) throw new Error(`Feed ${list.name} failed its integrity check`);
      await d.put('feeds', { name: list.name, m: list.m, k: list.k, count: list.count, updated: list.updated ?? manifest.generated, sha256: list.sha256, bits: buf });
    }
    const keep = new Set(manifest.lists.map((l) => l.name));
    for (const name of existing.keys()) if (!keep.has(name)) await d.delete('feeds', name);
    intel = build(await d.getAll('feeds'));
    loaded = true;
    await kvSet('feedStatus', { lastCheck: now, lastSuccess: now, error: null });
  } catch (e) {
    error = e instanceof Error ? e.message : String(e);
    await kvSet('feedStatus', { lastCheck: now, lastSuccess: prev.lastSuccess, error });
  }
  return feedStatus();
}

export function invalidateIntel(): void {
  loaded = false;
  intel = null;
}
