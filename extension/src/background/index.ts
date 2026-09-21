// Background event page: hosts the engine, the evidence store and the threat feeds.
import { ext } from '../shared/ext';
import { loadSettings, onSettingsChanged } from '../shared/settings';
import type { Request, ReportSummary, Stats, StoredReport } from '../shared/protocol';
import { db, wipe } from './db';
import { analyzeAndStore, summaryOf } from './pipeline';
import { feedStatus, invalidateIntel, refreshFeeds } from './feeds';
import { rebuildCampaign, sortCampaigns } from './campaigns';

const FEED_ALARM = 'mailshark-feeds';
const FEED_PERIOD_MIN = 12 * 60;

async function stats(): Promise<Stats> {
  const d = await db();
  const members = await d.getAll('members');
  const campaigns = await d.getAll('campaigns');
  const dayStart = new Date();
  dayStart.setHours(0, 0, 0, 0);
  const reports = d.transaction('reports').store.index('storedAt');
  const first = await reports.openCursor();
  const s: Stats = {
    total: members.length,
    danger: 0,
    caution: 0,
    safe: 0,
    campaigns: campaigns.length,
    threatCampaigns: campaigns.filter((c) => c.verdict !== 'safe').length,
    since: first?.value.meta.storedAt ?? null,
    today: { total: 0, danger: 0, caution: 0 },
    brands: [],
    intents: [],
  };
  const brands = new Map<string, number>();
  const intents = new Map<string, number>();
  const todayIds = new Set<string>();
  let cursor = await d.transaction('reports').store.index('storedAt').openCursor(IDBKeyRange.lowerBound(dayStart.getTime()));
  while (cursor) {
    todayIds.add(cursor.value.id);
    cursor = await cursor.continue();
  }
  for (const m of members) {
    s[m.verdict]++;
    if (todayIds.has(m.id)) {
      s.today.total++;
      if (m.verdict === 'danger') s.today.danger++;
      if (m.verdict === 'caution') s.today.caution++;
    }
    if (m.verdict !== 'safe') {
      if (m.fp.content.brand) brands.set(m.fp.content.brand, (brands.get(m.fp.content.brand) ?? 0) + 1);
      if (m.fp.content.intent) intents.set(m.fp.content.intent, (intents.get(m.fp.content.intent) ?? 0) + 1);
    }
  }
  s.brands = [...brands.entries()].map(([id, count]) => ({ id, count })).sort((a, b) => b.count - a.count).slice(0, 8);
  s.intents = [...intents.entries()].map(([id, count]) => ({ id, count })).sort((a, b) => b.count - a.count).slice(0, 8);
  return s;
}

async function history(limit: number, offset: number, verdict: string | undefined, query: string | undefined): Promise<{ items: ReportSummary[]; total: number }> {
  const d = await db();
  const q = (query ?? '').trim().toLowerCase();
  const page: StoredReport[] = [];
  let total = 0;
  // Collect first, summarise after: awaiting another transaction inside the cursor loop would let
  // this one auto-commit and the next continue() would throw.
  let cursor = await d.transaction('reports').store.index('storedAt').openCursor(null, 'prev');
  while (cursor) {
    const r = cursor.value;
    const okVerdict = !verdict || verdict === 'all' || r.report.verdict === verdict;
    const okQuery =
      !q ||
      r.report.summary.subject.toLowerCase().includes(q) ||
      (r.report.summary.from?.address ?? '').includes(q) ||
      (r.report.summary.from?.name ?? '').toLowerCase().includes(q) ||
      (r.meta.fileName ?? '').toLowerCase().includes(q);
    if (okVerdict && okQuery) {
      if (total >= offset && page.length < limit) page.push(r);
      total++;
    }
    cursor = await cursor.continue();
  }
  return { items: await Promise.all(page.map(summaryOf)), total };
}

async function handle(msg: Request): Promise<unknown> {
  switch (msg.kind) {
    case 'analyze': {
      try {
        const summary = await analyzeAndStore(msg.raw, msg.meta, msg.force ?? false);
        return { ok: true, summary };
      } catch (e) {
        return { ok: false, error: e instanceof Error ? e.message : String(e) };
      }
    }
    case 'summaries': {
      const d = await db();
      const out: Record<string, ReportSummary> = {};
      for (const id of msg.messageIds.slice(0, 200)) {
        const r = await d.getFromIndex('reports', 'messageId', id);
        if (r) out[id] = await summaryOf(r);
      }
      return out;
    }
    case 'report':
      return (await (await db()).get('reports', msg.id)) ?? null;
    case 'campaign': {
      const d = await db();
      const campaign = await d.get('campaigns', msg.id);
      if (!campaign) return null;
      const members: ReportSummary[] = [];
      for (const id of campaign.members) {
        const r = await d.get('reports', id);
        if (r) members.push(await summaryOf(r));
      }
      return { campaign, members };
    }
    case 'campaigns':
      return sortCampaigns(await (await db()).getAll('campaigns'));
    case 'history':
      return history(Math.min(200, msg.limit), msg.offset, msg.verdict, msg.query);
    case 'stats':
      return stats();
    case 'feedStatus':
      return feedStatus();
    case 'refreshFeeds':
      return refreshFeeds();
    case 'deleteReport': {
      const d = await db();
      const rep = await d.get('reports', msg.id);
      await d.delete('reports', msg.id);
      await d.delete('members', msg.id);
      if (rep?.meta.clusterId) await rebuildCampaign(d, rep.meta.clusterId);
      return { ok: true };
    }
    case 'deleteAll':
      await wipe();
      return { ok: true };
    case 'exportAll': {
      const d = await db();
      const json = JSON.stringify(
        { schema: 'mailshark.export/1', exportedAt: new Date().toISOString(), reports: await d.getAll('reports'), campaigns: await d.getAll('campaigns') },
        null,
        1,
      );
      return { json };
    }
    case 'openLab':
      await ext.tabs.create({ url: ext.runtime.getURL('lab.html') + (msg.route ? `#/${msg.route}` : '') });
      return { ok: true };
    default:
      return null;
  }
}

ext.runtime.onMessage.addListener((msg: unknown, sender: browser.runtime.MessageSender) => {
  // Only accept messages from this extension's own pages and content scripts.
  if (sender.id !== ext.runtime.id) return undefined;
  if (!msg || typeof msg !== 'object' || typeof (msg as { kind?: unknown }).kind !== 'string') return undefined;
  if ((msg as { kind: string }).kind.startsWith('tab:')) return undefined;
  return handle(msg as Request);
});

ext.runtime.onInstalled.addListener((details) => {
  if (details.reason === 'install') void ext.tabs.create({ url: ext.runtime.getURL('welcome.html') });
  void ext.alarms.create(FEED_ALARM, { delayInMinutes: 1, periodInMinutes: FEED_PERIOD_MIN });
});

ext.runtime.onStartup.addListener(() => {
  void ext.alarms.get(FEED_ALARM).then((a) => {
    if (!a) void ext.alarms.create(FEED_ALARM, { delayInMinutes: 1, periodInMinutes: FEED_PERIOD_MIN });
  });
});

ext.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === FEED_ALARM) void refreshFeeds();
});

let feedsEnabled: boolean | null = null;
void loadSettings().then((s) => {
  feedsEnabled = s.feeds;
});
onSettingsChanged((s) => {
  if (s.feeds === feedsEnabled) return;
  feedsEnabled = s.feeds;
  invalidateIntel();
  if (s.feeds) void refreshFeeds();
});
