// Campaign correlation over the local evidence store.
import { assignCampaign, newCampaignId, profileCampaign, type CampaignMember } from '../../../engine/src/campaign/cluster';
import type { Fingerprint, Verdict } from '../../../engine/src/types';
import { brandById } from '../../../engine/src/data/brands';
import type { CampaignBrief, CampaignRecord } from '../shared/protocol';
import { db, MAX_KEY_FANOUT, type DB, type MemberRow } from './db';

const MAX_CANDIDATES = 300;

const INTENT_LABEL: Record<string, string> = {
  credential: 'credential lure', payment: 'payment fraud', giftcard: 'gift-card scam', crypto: 'crypto theft', mfa: 'MFA-code theft',
  delivery: 'delivery scam', document: 'fake shared document', tax: 'tax/government lure', job: 'job scam', reward: 'prize lure',
  extortion: 'extortion', callback: 'call-back scam', bec: 'CEO fraud',
};

function mode<T>(values: (T | null | undefined)[]): T | null {
  const counts = new Map<T, number>();
  for (const v of values) if (v !== null && v !== undefined) counts.set(v, (counts.get(v) ?? 0) + 1);
  let best: T | null = null;
  let n = 0;
  for (const [v, c] of counts) if (c > n) [best, n] = [v, c];
  return best;
}

function labelFor(fps: Fingerprint[], verdict: Verdict): string {
  const brand = mode(fps.map((f) => f.content.brand));
  const intent = mode(fps.map((f) => f.content.intent));
  const brandName = brand ? (brandById(brand)?.name ?? brand) : null;
  if (intent && verdict !== 'safe') return `${brandName ? brandName + ' ' : ''}${INTENT_LABEL[intent] ?? intent}`.replace(/^./, (c) => c.toUpperCase());
  const sender = mode(fps.map((f) => f.sender.displayName)) ?? mode(fps.map((f) => f.sender.fromOrg));
  if (verdict === 'safe') return `Bulk mail · ${sender ?? brandName ?? 'unknown sender'}`;
  if (brandName) return `${brandName} impersonation`;
  const subject = mode(fps.map((f) => f.content.subjectTemplate));
  return subject ? `“${subject.slice(0, 48)}${subject.length > 48 ? '…' : ''}”` : 'Unlabelled campaign';
}

const RANK: Record<Verdict, number> = { safe: 0, caution: 1, danger: 2 };

async function candidates(d: DB, fp: Fingerprint, selfId: string): Promise<MemberRow[]> {
  const hits = new Map<string, number>();
  for (const key of fp.keys) {
    const row = await d.get('keys', key);
    if (!row) continue;
    // Very common keys (e.g. a free-mail provider) carry little signal: sample their newest ids.
    const ids = row.ids.length > 60 ? row.ids.slice(-60) : row.ids;
    for (const id of ids) if (id !== selfId) hits.set(id, (hits.get(id) ?? 0) + 1);
  }
  const ranked = [...hits.entries()].sort((a, b) => b[1] - a[1]).slice(0, MAX_CANDIDATES);
  const rows = await Promise.all(ranked.map(([id]) => d.get('members', id)));
  return rows.filter((r): r is MemberRow => !!r);
}

export async function rebuildCampaign(d: DB, id: string): Promise<CampaignRecord | null> {
  const rows = await d.getAllFromIndex('members', 'clusterId', id);
  if (rows.length < 2) {
    await d.delete('campaigns', id);
    for (const r of rows) await d.put('members', { ...r, clusterId: null });
    return null;
  }
  const prev = await d.get('campaigns', id);
  const fps = rows.map((r) => r.fp);
  const verdictCounts: Record<Verdict, number> = { safe: 0, caution: 0, danger: 0 };
  for (const r of rows) verdictCounts[r.verdict]++;
  const verdict: Verdict = verdictCounts.danger ? 'danger' : verdictCounts.caution ? 'caution' : 'safe';
  const record: CampaignRecord = {
    id,
    label: labelFor(fps, verdict),
    members: rows.sort((a, b) => a.time - b.time).map((r) => r.id),
    createdAt: prev?.createdAt ?? Date.now(),
    updatedAt: Date.now(),
    maxScore: Math.max(...rows.map((r) => r.score)),
    verdict,
    verdictCounts,
    intent: mode(fps.map((f) => f.content.intent)),
    brand: mode(fps.map((f) => f.content.brand)),
    profile: profileCampaign(fps),
  };
  await d.put('campaigns', record);
  return record;
}

/** Index the fingerprint, find its campaign (creating/merging as needed) and return a brief. */
export async function correlate(self: MemberRow): Promise<CampaignBrief | null> {
  const d = await db();
  const cands = await candidates(d, self.fp, self.id);
  const members: CampaignMember[] = cands.map((c) => ({ id: c.id, clusterId: c.clusterId, fp: c.fp, score: c.score, verdict: c.verdict }));
  const a = assignCampaign(self.fp, members, self.id);

  let clusterId = a.clusterId;
  if (!clusterId && a.matches.length) clusterId = newCampaignId(self.id + ':' + a.matches[0]!.id);
  if (clusterId) {
    // Pull in unclustered look-alikes and merge overlapping campaigns.
    for (const m of a.matches) {
      if (m.clusterId === clusterId) continue;
      if (m.clusterId === null || a.merge.includes(m.clusterId)) {
        const row = await d.get('members', m.id);
        if (row) await d.put('members', { ...row, clusterId });
      }
    }
    for (const other of a.merge) {
      const rows = await d.getAllFromIndex('members', 'clusterId', other);
      for (const r of rows) await d.put('members', { ...r, clusterId });
      await d.delete('campaigns', other);
    }
  }
  await d.put('members', { ...self, clusterId });

  // Inverted index for future candidate lookups.
  for (const key of self.fp.keys) {
    const row = (await d.get('keys', key)) ?? { key, ids: [] };
    if (!row.ids.includes(self.id)) {
      row.ids.push(self.id);
      if (row.ids.length > MAX_KEY_FANOUT) row.ids.splice(0, row.ids.length - MAX_KEY_FANOUT);
      await d.put('keys', row);
    }
  }

  if (!clusterId) return null;
  const record = await rebuildCampaign(d, clusterId);
  if (!record) return null;
  // Keep report metadata in sync for every member of the (possibly merged) campaign.
  const tx = d.transaction('reports', 'readwrite');
  for (const id of record.members) {
    const rep = await tx.store.get(id);
    if (rep && rep.meta.clusterId !== record.id) await tx.store.put({ ...rep, meta: { ...rep.meta, clusterId: record.id } });
  }
  await tx.done;
  return brief(record);
}

export function brief(c: CampaignRecord): CampaignBrief {
  return { id: c.id, label: c.label, size: c.members.length, verdict: c.verdict, maxScore: c.maxScore };
}

export function sortCampaigns(list: CampaignRecord[]): CampaignRecord[] {
  return [...list].sort((a, b) => RANK[b.verdict] - RANK[a.verdict] || b.members.length - a.members.length || b.updatedAt - a.updatedAt);
}
