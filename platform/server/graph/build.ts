// Investigation graph: real entities from analysis and correlation, never decoration.
//   nodes  messages, local clusters, external campaign records, indicators (by role)
//   edges  message→indicator (where it was observed), member-of, similar-to (with evidence),
//          indicator→external event (reported-in)
// Large investigations are reduced by explicit priority, and the response says exactly what was
// hidden and why, so nothing disappears silently.
import type { Db } from '../db/sqlite';

export type NodeKind = 'message' | 'cluster' | 'external' | 'sender' | 'sender-domain' | 'reply-to' | 'domain' | 'hostname' | 'url' | 'ip' | 'attachment' | 'phone' | 'wallet' | 'recipient';
export const NODE_KINDS: NodeKind[] = ['message', 'cluster', 'external', 'sender', 'sender-domain', 'reply-to', 'domain', 'hostname', 'url', 'ip', 'attachment', 'phone', 'wallet', 'recipient'];
export const DEFAULT_KINDS: NodeKind[] = ['message', 'cluster', 'external', 'sender', 'reply-to', 'domain', 'ip', 'attachment', 'phone', 'wallet'];

export interface GraphQuery {
  kinds: Set<NodeKind>;
  classes: Set<string> | null;
  from: number | null;
  to: number | null;
  minEdge: number;
  sources: Set<string> | null;
  q: string | null;
  focus: string[];
  depth: number;
  limit: number;
  similarity: boolean;
  minDegree: number;
  cluster: string | null;
}

export interface GNode {
  id: string;
  kind: NodeKind;
  label: string;
  sublabel?: string | null;
  cls?: string | null;
  severity?: string | null;
  score?: number | null;
  time?: number | null;
  intel?: { sources: string[]; strongest: number; threats: string[] } | null;
  suspicious?: boolean;
  degree: number;
  ref?: string;
  data?: Record<string, unknown>;
}

export interface GEdge {
  id: string;
  source: string;
  target: string;
  kind: 'sent-by' | 'sender-domain' | 'replies-to' | 'links-to' | 'sent-from' | 'composed-from' | 'carries' | 'mentions' | 'pays-to' | 'addressed-to' | 'submitted-by' | 'bounces-to' | 'member-of' | 'similar-to' | 'reported-in' | 'matches';
  weight: number;
  tier?: 'exact' | 'probable';
  evidence: Record<string, unknown>[];
}

export interface GraphPayload {
  nodes: GNode[];
  edges: GEdge[];
  totals: { nodes: number; edges: number };
  hidden: Partial<Record<NodeKind, number>>;
  hiddenReason: string | null;
  focus: string[];
  kindsAvailable: Partial<Record<NodeKind, number>>;
}

function kindFor(type: string, role: string): NodeKind | null {
  if (type === 'email' && (role === 'from' || role === 'authenticated-sender' || role === 'return-path' || role === 'display-name-address')) return 'sender';
  if (type === 'email' && role === 'reply-to') return 'reply-to';
  if (type === 'email' && role === 'recipient') return 'recipient';
  if (type === 'domain' && role === 'from') return 'sender-domain';
  if (type === 'domain' && role === 'link-domain') return 'domain';
  if (type === 'hostname' && role === 'link-host') return 'hostname';
  if (type === 'url' && (role === 'link' || role === 'qr-link' || role === 'attachment-link')) return 'url';
  if ((type === 'ipv4' || type === 'ipv6') && (role === 'origin-ip' || role === 'client-ip' || role === 'link-host')) return 'ip';
  if (type === 'sha256' && role === 'attachment') return 'attachment';
  if (type === 'phone') return 'phone';
  if (type === 'btc' || type === 'eth' || type === 'xmr') return 'wallet';
  return null;
}

const EDGE_FOR_ROLE: Record<string, GEdge['kind']> = {
  from: 'sent-by',
  'reply-to': 'replies-to',
  'return-path': 'bounces-to',
  'authenticated-sender': 'submitted-by',
  'display-name-address': 'sent-by',
  recipient: 'addressed-to',
  'link-domain': 'links-to',
  'link-host': 'links-to',
  link: 'links-to',
  'qr-link': 'links-to',
  'attachment-link': 'links-to',
  'origin-ip': 'sent-from',
  'client-ip': 'composed-from',
  attachment: 'carries',
  body: 'mentions',
};

const CLASS_RANK: Record<string, number> = { malicious: 800, suspicious: 700, inconclusive: 450, failed: 400, benign: 300 };

export function buildGraph(db: Db, caseId: string, q: GraphQuery): GraphPayload {
  const nodes = new Map<string, GNode>();
  const edges = new Map<string, GEdge>();
  const addEdge = (e: Omit<GEdge, 'id'>): void => {
    const id = `${e.kind}:${e.source}>${e.target}`;
    const cur = edges.get(id);
    if (cur) {
      cur.evidence.push(...e.evidence);
      cur.weight = Math.max(cur.weight, e.weight);
    } else edges.set(id, { id, ...e });
  };

  // 1. Messages
  const msgs = db.all<{ id: string; subject: string | null; from_addr: string | null; from_name: string | null; class: string | null; severity: string | null; score: number | null; sent_at: number | null; created_at: number; intel_hits: number; cluster_id: string | null; status: string }>(
    "SELECT id, subject, from_addr, from_name, class, severity, score, sent_at, created_at, intel_hits, cluster_id, status FROM messages WHERE case_id = ? AND status IN ('analyzed', 'failed')",
    caseId,
  );
  const kept = msgs.filter((m) => {
    if (q.classes && !q.classes.has(m.class ?? 'unknown')) return false;
    const t = m.sent_at ?? m.created_at;
    if (q.from !== null && t < q.from) return false;
    if (q.to !== null && t > q.to) return false;
    if (q.cluster && m.cluster_id !== q.cluster) return false;
    return true;
  });
  const keptIds = new Set(kept.map((m) => m.id));
  for (const m of kept) {
    nodes.set(`m:${m.id}`, {
      id: `m:${m.id}`,
      kind: 'message',
      label: m.subject || '(no subject)',
      sublabel: m.from_name ? `${m.from_name} <${m.from_addr ?? ''}>` : m.from_addr,
      cls: m.class,
      severity: m.severity,
      score: m.score,
      time: m.sent_at ?? m.created_at,
      degree: 0,
      ref: m.id,
      data: { intelHits: m.intel_hits, clusterId: m.cluster_id, status: m.status },
    });
  }

  // 2. Clusters
  if (q.kinds.has('cluster')) {
    for (const c of db.all<{ id: string; label: string; size: number; confidence: string; verdict: string; cohesion: number; profile_json: string; first_seen: number | null }>('SELECT id, label, size, confidence, verdict, cohesion, profile_json, first_seen FROM clusters WHERE case_id = ?', caseId)) {
      const profile = JSON.parse(c.profile_json) as { members: { id: string; strength: number }[]; exactEdges: number };
      const members = profile.members.filter((m) => keptIds.has(m.id));
      if (!members.length) continue;
      nodes.set(`c:${c.id}`, { id: `c:${c.id}`, kind: 'cluster', label: c.label, sublabel: `${c.size} messages · ${c.confidence} confidence`, cls: c.verdict === 'bulk' ? 'benign' : 'malicious', time: c.first_seen, degree: 0, ref: c.id, data: { size: c.size, confidence: c.confidence, verdict: c.verdict, cohesion: c.cohesion, exactEdges: profile.exactEdges } });
      for (const m of members) addEdge({ source: `m:${m.id}`, target: `c:${c.id}`, kind: 'member-of', weight: m.strength, evidence: [{ membership: m.strength }] });
    }
  }

  // 3. Indicators observed in the kept messages
  const intelByIndicator = new Map<number, { sources: Set<string>; strongest: number; threats: Set<string> }>();
  for (const r of db.all<{ indicator_id: number; source: string; strength: number; record_json: string }>('SELECT indicator_id, source, strength, record_json FROM intel_matches WHERE case_id = ? AND strength > 0', caseId)) {
    const cur = intelByIndicator.get(r.indicator_id) ?? { sources: new Set<string>(), strongest: 0, threats: new Set<string>() };
    cur.sources.add(r.source);
    cur.strongest = Math.max(cur.strongest, r.strength);
    const rec = JSON.parse(r.record_json) as { threat?: string | null; family?: string | null };
    if (rec.family) cur.threats.add(rec.family);
    else if (rec.threat) cur.threats.add(rec.threat);
    intelByIndicator.set(r.indicator_id, cur);
  }
  const obs = db.all<{ message_id: string; indicator_id: number; type: string; value: string; role: string; ref: string; context: string | null; suspicious: number }>(
    'SELECT o.message_id, o.indicator_id, i.type, i.value, o.role, o.ref, o.context, o.suspicious FROM observations o JOIN indicators i ON i.id = o.indicator_id WHERE o.case_id = ?',
    caseId,
  );
  const fileNames = new Map<string, string>();
  for (const o of obs) if (o.type === 'filename' && o.role === 'attachment-name') fileNames.set(`${o.message_id}|${o.ref}`, o.value);
  const kindsAvailable: Partial<Record<NodeKind, number>> = { message: kept.length };
  const seenKinds = new Map<NodeKind, Set<number>>();
  const indicatorNodeId = new Map<string, string>();
  for (const o of obs) {
    if (!keptIds.has(o.message_id)) continue;
    const kind = kindFor(o.type, o.role);
    if (!kind) continue;
    (seenKinds.get(kind) ?? seenKinds.set(kind, new Set()).get(kind))?.add(o.indicator_id);
    if (!q.kinds.has(kind)) continue;
    const intel = intelByIndicator.get(o.indicator_id);
    if (q.sources && !(intel && [...intel.sources].some((s) => q.sources?.has(s)))) continue;
    const nid = `i:${o.indicator_id}`;
    indicatorNodeId.set(`${o.type}|${o.value}`, nid);
    if (!nodes.has(nid)) {
      const label = kind === 'attachment' ? (fileNames.get(`${o.message_id}|${o.ref}`) ?? `${o.value.slice(0, 12)}…`) : o.value;
      nodes.set(nid, {
        id: nid,
        kind,
        label,
        sublabel: kind === 'attachment' ? `SHA-256 ${o.value.slice(0, 16)}…` : o.type,
        intel: intel ? { sources: [...intel.sources], strongest: intel.strongest, threats: [...intel.threats].slice(0, 5) } : null,
        suspicious: !!o.suspicious,
        degree: 0,
        ref: String(o.indicator_id),
        data: { type: o.type, value: o.value },
      });
    } else if (o.suspicious) (nodes.get(nid) as GNode).suspicious = true;
    addEdge({ source: `m:${o.message_id}`, target: nid, kind: EDGE_FOR_ROLE[o.role] ?? 'mentions', weight: 1, evidence: [{ messageId: o.message_id, role: o.role, ref: o.ref, context: o.context }] });
  }
  for (const [k, ids] of seenKinds) kindsAvailable[k] = ids.size;

  // 4. External campaign records
  if (q.kinds.has('external')) {
    const typeMap: Record<string, string[]> = { domain: ['hostname', 'domain'], ip: ['ipv4', 'ipv6'], url: ['url'], email: ['email'], md5: ['md5'], sha1: ['sha1'], sha256: ['sha256'], phone: ['phone'], btc: ['btc'], subject: [], filename: [] };
    const ext = db.all<{ source: string; event_id: string; name: string; assessment: string; confidence: string; detail_json: string }>('SELECT source, event_id, name, assessment, confidence, detail_json FROM external_campaigns WHERE case_id = ?', caseId);
    kindsAvailable.external = ext.length;
    for (const x of ext) {
      const d = JSON.parse(x.detail_json) as { messages: string[]; indicators: { type: string; value: string; matchType: string; strength: number }[]; date: number | null; reference: string | null; org: string | null };
      const msgsIn = d.messages.filter((id) => keptIds.has(id));
      if (!msgsIn.length) continue;
      if (q.sources && !q.sources.has(x.source)) continue;
      const nid = `x:${x.source}:${x.event_id}`;
      nodes.set(nid, { id: nid, kind: 'external', label: x.name, sublabel: `${x.source} · ${x.assessment === 'reported-association' ? 'reported association' : 'possible association'}`, time: d.date, degree: 0, ref: `${x.source}/${x.event_id}`, data: { source: x.source, eventId: x.event_id, assessment: x.assessment, confidence: x.confidence, reference: d.reference, org: d.org } });
      let linked = false;
      for (const ind of d.indicators.filter((i) => i.strength > 0)) {
        for (const t of typeMap[ind.type] ?? []) {
          const src = indicatorNodeId.get(`${t}|${ind.value}`);
          if (src && nodes.has(src)) {
            addEdge({ source: src, target: nid, kind: 'reported-in', weight: ind.strength, evidence: [{ matchType: ind.matchType, strength: ind.strength, value: ind.value }] });
            linked = true;
          }
        }
      }
      if (!linked) for (const id of msgsIn) addEdge({ source: `m:${id}`, target: nid, kind: 'matches', weight: 0.5, evidence: [{ note: 'matched indicators are hidden by the current type filter' }] });
    }
  }

  // 5. Message-to-message relationships
  if (q.similarity) {
    for (const e of db.all<{ a: string; b: string; tier: 'exact' | 'probable'; score: number; evidence_json: string }>('SELECT a, b, tier, score, evidence_json FROM edges WHERE case_id = ? AND score >= ?', caseId, q.minEdge)) {
      if (!keptIds.has(e.a) || !keptIds.has(e.b)) continue;
      const ev = JSON.parse(e.evidence_json) as { shared: unknown[]; layers: unknown; hardLink: string | null };
      addEdge({ source: `m:${e.a}`, target: `m:${e.b}`, kind: 'similar-to', weight: e.score, tier: e.tier, evidence: [{ shared: ev.shared.slice(0, 6), layers: ev.layers, hardLink: ev.hardLink }] });
    }
  }

  // Degrees; drop indicators below the minimum degree (e.g. "shared indicators only").
  const recount = (): void => {
    for (const n of nodes.values()) n.degree = 0;
    for (const e of edges.values()) {
      const s = nodes.get(e.source);
      const t = nodes.get(e.target);
      if (s) s.degree++;
      if (t) t.degree++;
    }
  };
  recount();
  if (q.minDegree > 1) {
    for (const [id, n] of nodes) if (n.id.startsWith('i:') && n.degree < q.minDegree) nodes.delete(id);
    for (const [id, e] of edges) if (!nodes.has(e.source) || !nodes.has(e.target)) edges.delete(id);
    recount();
  }

  // Focus / search → neighbourhood.
  let focus = q.focus.filter((f) => nodes.has(f));
  if (q.q) {
    const needle = q.q.toLowerCase();
    focus = [...focus, ...[...nodes.values()].filter((n) => n.label.toLowerCase().includes(needle) || (n.sublabel ?? '').toLowerCase().includes(needle)).map((n) => n.id).slice(0, 50)];
  }
  if (focus.length) {
    const adj = new Map<string, string[]>();
    for (const e of edges.values()) {
      (adj.get(e.source) ?? adj.set(e.source, []).get(e.source))?.push(e.target);
      (adj.get(e.target) ?? adj.set(e.target, []).get(e.target))?.push(e.source);
    }
    const keep = new Set(focus);
    let frontier = [...focus];
    for (let d = 0; d < q.depth; d++) {
      const next: string[] = [];
      for (const f of frontier) for (const nb of adj.get(f) ?? []) if (!keep.has(nb)) {
        keep.add(nb);
        next.push(nb);
      }
      frontier = next;
    }
    for (const id of [...nodes.keys()]) if (!keep.has(id)) nodes.delete(id);
    for (const [id, e] of edges) if (!nodes.has(e.source) || !nodes.has(e.target)) edges.delete(id);
    recount();
  }

  const totals = { nodes: nodes.size, edges: edges.size };
  const hidden: Partial<Record<NodeKind, number>> = {};
  let hiddenReason: string | null = null;
  if (nodes.size > q.limit) {
    const focusSet = new Set(focus);
    const priority = (n: GNode): number => {
      if (focusSet.has(n.id)) return 1e9;
      if (n.kind === 'cluster') return 1e6 + ((n.data?.['size'] as number) ?? 0);
      if (n.kind === 'external') return 9e5;
      if (n.kind === 'message') return (CLASS_RANK[n.cls ?? ''] ?? 200) * 1000 + (n.score ?? 0);
      return 100 + (n.intel ? 5000 * n.intel.strongest : 0) + (n.suspicious ? 2000 : 0) + n.degree * 50;
    };
    const ranked = [...nodes.values()].sort((a, b) => priority(b) - priority(a));
    for (const n of ranked.slice(q.limit)) {
      hidden[n.kind] = (hidden[n.kind] ?? 0) + 1;
      nodes.delete(n.id);
    }
    for (const [id, e] of edges) if (!nodes.has(e.source) || !nodes.has(e.target)) edges.delete(id);
    recount();
    hiddenReason = `Showing the ${q.limit} highest-priority entities (threat messages, clusters, external campaigns and the most connected or intelligence-listed indicators). Use filters or search to see the rest.`;
  }
  return { nodes: [...nodes.values()], edges: [...edges.values()], totals, hidden, hiddenReason, focus, kindsAvailable };
}
