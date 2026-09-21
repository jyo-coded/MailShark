// Incremental campaign clustering + "what changed vs. what stayed the same" analysis.
import type { Fingerprint, Verdict } from '../types';
import { similarity, type Similarity } from './similarity';
import { hash53 } from '../util/hash';

export const JOIN_THRESHOLD = 0.6;
export const MERGE_THRESHOLD = 0.72;

export interface CampaignMember {
  id: string;
  clusterId: string | null;
  fp: Fingerprint;
  score: number;
  verdict: Verdict;
}

export interface Assignment {
  clusterId: string | null; // null → start a new campaign
  merge: string[]; // other clusters that should be merged into clusterId
  matches: { id: string; clusterId: string | null; similarity: Similarity }[];
}

export function newCampaignId(seed: string): string {
  return 'C-' + hash53(seed).slice(-6).toUpperCase();
}

/** Decide which campaign a new fingerprint joins, given candidate members from the index. */
export function assignCampaign(fp: Fingerprint, candidates: CampaignMember[], selfId: string): Assignment {
  const matches = candidates
    .filter((c) => c.id !== selfId)
    .map((c) => ({ id: c.id, clusterId: c.clusterId, similarity: similarity(fp, c.fp) }))
    .filter((m) => m.similarity.score >= JOIN_THRESHOLD)
    .sort((a, b) => b.similarity.score - a.similarity.score);
  if (!matches.length) return { clusterId: null, merge: [], matches: [] };

  const best = new Map<string, number>();
  for (const m of matches) {
    if (!m.clusterId) continue;
    best.set(m.clusterId, Math.max(best.get(m.clusterId) ?? 0, m.similarity.score));
  }
  const ranked = [...best.entries()].sort((a, b) => b[1] - a[1]);
  const target = ranked[0]?.[0] ?? null;
  const merge = ranked.slice(1).filter(([, s]) => s >= MERGE_THRESHOLD).map(([id]) => id);
  return { clusterId: target, merge, matches: matches.slice(0, 25) };
}

// ── Invariant analysis ──────────────────────────────────────────────────────

export interface AttributeSpread {
  attr: string;
  label: string;
  values: string[];
  coverage: number; // share of members that have this attribute
}

export interface CampaignProfile {
  size: number;
  invariants: AttributeSpread[];
  rotated: AttributeSpread[];
  attackerCost: number;
  firstSeen: number;
  lastSeen: number;
  senders: string[];
  domains: string[];
  attachments: number;
}

type Extract = (fp: Fingerprint) => string[];

const ATTRS: { attr: string; label: string; get: Extract }[] = [
  { attr: 'fromOrg', label: 'Sender domain', get: (f) => (f.sender.fromOrg ? [f.sender.fromOrg] : []) },
  { attr: 'displayName', label: 'Sender name', get: (f) => (f.sender.displayName ? [f.sender.displayName] : []) },
  { attr: 'localTemplate', label: 'Mailbox pattern', get: (f) => (f.sender.localTemplate ? [f.sender.localTemplate] : []) },
  { attr: 'replyToOrg', label: 'Reply-To domain', get: (f) => (f.sender.replyToOrg ? [f.sender.replyToOrg] : []) },
  { attr: 'originNet', label: 'Sending network', get: (f) => (f.infra.originNet ? [f.infra.originNet] : []) },
  { attr: 'originOrg', label: 'Sending server org', get: (f) => (f.infra.originOrg ? [f.infra.originOrg] : []) },
  { attr: 'xMailer', label: 'Mailer software', get: (f) => (f.infra.xMailer ? [f.infra.xMailer] : []) },
  { attr: 'dkim', label: 'DKIM signing domain', get: (f) => f.infra.dkimDomains },
  { attr: 'headerOrder', label: 'Header fingerprint', get: (f) => (f.infra.headerOrder ? [f.infra.headerOrder] : []) },
  { attr: 'msgid', label: 'Message-ID pattern', get: (f) => (f.infra.messageIdTemplate ? [f.infra.messageIdTemplate] : []) },
  { attr: 'espCampaign', label: 'Bulk-mail campaign ID', get: (f) => (f.infra.espCampaign ? [f.infra.espCampaign] : []) },
  { attr: 'subject', label: 'Subject template', get: (f) => (f.content.subjectTemplate ? [f.content.subjectTemplate] : []) },
  { attr: 'skeleton', label: 'HTML template', get: (f) => (f.content.skeleton ? [f.content.skeleton] : []) },
  { attr: 'intent', label: 'Lure type', get: (f) => (f.content.intent ? [f.content.intent] : []) },
  { attr: 'brand', label: 'Brand used', get: (f) => (f.content.brand ? [f.content.brand] : []) },
  { attr: 'linkDomain', label: 'Link domains', get: (f) => f.urls.domains },
  { attr: 'linkTemplate', label: 'Landing-page URL', get: (f) => f.urls.templates },
  { attr: 'linkPath', label: 'Phishing-kit path', get: (f) => f.urls.paths },
  { attr: 'attHash', label: 'Attachment hash', get: (f) => f.attachments.sha256 },
  { attr: 'attStruct', label: 'Attachment structure', get: (f) => f.attachments.structural },
  { attr: 'attName', label: 'Attachment name pattern', get: (f) => f.attachments.nameTemplates },
];

export function profileCampaign(members: Fingerprint[]): CampaignProfile {
  const size = members.length;
  const invariants: AttributeSpread[] = [];
  const rotated: AttributeSpread[] = [];
  for (const { attr, label, get } of ATTRS) {
    const values = new Map<string, number>();
    let have = 0;
    for (const fp of members) {
      const vs = get(fp);
      if (vs.length) have++;
      // Multi-valued attributes (link domains…) use the member's full set as one "value".
      const key = vs.length > 1 ? [...vs].sort().join(' + ') : (vs[0] ?? null);
      if (key) values.set(key, (values.get(key) ?? 0) + 1);
    }
    if (!have) continue;
    const spread: AttributeSpread = { attr, label, values: [...values.keys()].slice(0, 12), coverage: have / size };
    if (values.size === 1 && have >= Math.max(2, Math.ceil(size * 0.6))) invariants.push(spread);
    else if (values.size > 1) rotated.push(spread);
  }
  const times = members.map((m) => m.time).filter((t) => t > 0);
  return {
    size,
    invariants,
    rotated,
    attackerCost: invariants.length,
    firstSeen: times.length ? Math.min(...times) : 0,
    lastSeen: times.length ? Math.max(...times) : 0,
    senders: [...new Set(members.map((m) => m.sender.fromDomain).filter((x): x is string => !!x))],
    domains: [...new Set(members.flatMap((m) => m.urls.domains))],
    attachments: new Set(members.flatMap((m) => m.attachments.sha256)).size,
  };
}
