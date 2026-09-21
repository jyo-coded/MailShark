// Campaign relationship graph: emails ↔ the indicators that connect them (force-directed, static).
import { useEffect, useMemo, useState } from 'preact/hooks';
import { forceCenter, forceCollide, forceLink, forceManyBody, forceSimulation, type SimulationLinkDatum, type SimulationNodeDatum } from 'd3-force';
import type { Fingerprint, Verdict } from '../../../engine/src/types';
import { send } from '../shared/protocol';

type Kind = 'email' | 'sender' | 'domain' | 'network' | 'file' | 'kit';

interface Node extends SimulationNodeDatum {
  id: string;
  kind: Kind;
  label: string;
  verdict?: Verdict;
  reportId?: string;
  degree: number;
}

type Link = SimulationLinkDatum<Node> & { source: string | Node; target: string | Node };

const KIND_COLOR: Record<Kind, string> = {
  email: 'var(--ms-text-2)',
  sender: '#a78bfa',
  domain: '#38e1d6',
  network: '#60a5fa',
  file: '#f472b6',
  kit: '#fbbf24',
};
const KIND_LABEL: Record<Kind, string> = { email: 'Email', sender: 'Sender domain', domain: 'Link domain', network: 'Sending network', file: 'Attachment', kit: 'Kit path' };
const VERDICT_COLOR: Record<Verdict, string> = { danger: 'var(--ms-danger)', caution: 'var(--ms-caution)', safe: 'var(--ms-safe)' };

const W = 760;
const H = 380;

export function CampaignGraph({ memberIds, onOpen }: { memberIds: string[]; onOpen: (id: string) => void }) {
  const [data, setData] = useState<{ id: string; fp: Fingerprint; verdict: Verdict; subject: string }[] | null>(null);
  const [hover, setHover] = useState<string | null>(null);
  useEffect(() => {
    let alive = true;
    void Promise.all(memberIds.slice(0, 40).map((id) => send({ kind: 'report', id }))).then((rows) => {
      if (!alive) return;
      setData(rows.filter((r): r is NonNullable<typeof r> => !!r).map((r) => ({ id: r.id, fp: r.report.fingerprint, verdict: r.report.verdict, subject: r.report.summary.subject })));
    });
    return () => {
      alive = false;
    };
  }, [memberIds.join(',')]);

  const graph = useMemo(() => {
    if (!data) return null;
    const nodes = new Map<string, Node>();
    const links: Link[] = [];
    const add = (id: string, kind: Kind, label: string): Node => {
      let n = nodes.get(id);
      if (!n) {
        n = { id, kind, label, degree: 0 };
        nodes.set(id, n);
      }
      return n;
    };
    for (const m of data) {
      const e = add(`e:${m.id}`, 'email', m.subject || '(no subject)');
      e.verdict = m.verdict;
      e.reportId = m.id;
      const attach = (id: string, kind: Kind, label: string): void => {
        const n = add(id, kind, label);
        n.degree++;
        e.degree++;
        links.push({ source: e.id, target: n.id });
      };
      if (m.fp.sender.fromOrg) attach(`s:${m.fp.sender.fromOrg}`, 'sender', m.fp.sender.fromOrg);
      for (const d of m.fp.urls.domains.slice(0, 4)) attach(`d:${d}`, 'domain', d);
      if (m.fp.infra.originNet) attach(`n:${m.fp.infra.originNet}`, 'network', m.fp.infra.originNet);
      for (const h of m.fp.attachments.sha256.slice(0, 3)) attach(`f:${h}`, 'file', h.slice(0, 10) + '…');
      for (const p of m.fp.urls.paths.slice(0, 2)) attach(`k:${p}`, 'kit', p);
    }
    const list = [...nodes.values()];
    const sim = forceSimulation<Node>(list)
      .force('link', forceLink<Node, Link>(links).id((d) => d.id).distance((l) => ((l.target as Node).degree > 1 ? 110 : 52)).strength(0.6))
      .force('charge', forceManyBody().strength(-320))
      .force('center', forceCenter(W / 2, H / 2))
      .force('collide', forceCollide<Node>().radius((d) => (d.kind === 'email' ? 16 : 10)))
      .stop();
    for (let i = 0; i < 300; i++) sim.tick();
    for (const n of list) {
      n.x = Math.max(24, Math.min(W - 24, n.x ?? W / 2));
      n.y = Math.max(20, Math.min(H - 20, n.y ?? H / 2));
    }
    return { nodes: list, links };
  }, [data]);

  if (!graph) return <div class="ms-skeleton ms-graph" />;
  const neighbours = new Set<string>();
  if (hover) {
    for (const l of graph.links) {
      const s = (l.source as Node).id;
      const t = (l.target as Node).id;
      if (s === hover) neighbours.add(t);
      if (t === hover) neighbours.add(s);
    }
    neighbours.add(hover);
  }
  const kinds = [...new Set(graph.nodes.map((n) => n.kind))];
  return (
    <div>
      <svg class="ms-graph" viewBox={`0 0 ${W} ${H}`} role="img" aria-label="Campaign relationship graph" style={{ animation: 'ms-fade-in 500ms both' }}>
        {graph.links.map((l) => {
          const s = l.source as Node;
          const t = l.target as Node;
          const dim = hover && !(neighbours.has(s.id) && neighbours.has(t.id));
          return <line class="ms-g-link" x1={s.x} y1={s.y} x2={t.x} y2={t.y} style={{ opacity: dim ? 0.12 : 0.8 }} />;
        })}
        {graph.nodes.map((n) => {
          const dim = hover && !neighbours.has(n.id);
          const r = n.kind === 'email' ? 9 : 5 + Math.min(6, n.degree);
          const fill = n.kind === 'email' ? VERDICT_COLOR[n.verdict ?? 'safe'] : KIND_COLOR[n.kind];
          return (
            <g
              style={{ opacity: dim ? 0.2 : 1, transition: 'opacity 200ms', cursor: n.reportId ? 'pointer' : 'default' }}
              onMouseEnter={() => setHover(n.id)}
              onMouseLeave={() => setHover(null)}
              onClick={() => n.reportId && onOpen(n.reportId)}
            >
              {n.kind === 'email' ? <rect class="ms-g-node" x={(n.x ?? 0) - r} y={(n.y ?? 0) - r} width={r * 2} height={r * 2} rx={4} fill={fill} /> : <circle class="ms-g-node" cx={n.x} cy={n.y} r={r} fill={fill} />}
              {(hover === n.id || (n.kind !== 'email' && n.degree > 1)) && (
                <text x={(n.x ?? 0) + r + 4} y={(n.y ?? 0) + 3.5}>
                  {n.label.length > 34 ? n.label.slice(0, 33) + '…' : n.label}
                </text>
              )}
              <title>{`${KIND_LABEL[n.kind]}: ${n.label}`}</title>
            </g>
          );
        })}
      </svg>
      <div class="ms-row" style={{ flexWrap: 'wrap', gap: '12px', marginTop: '10px', fontSize: '12px' }}>
        {kinds.map((k) => (
          <span class="ms-row" style={{ gap: '6px' }}>
            <span class="ms-dot" style={{ color: k === 'email' ? 'var(--ms-danger)' : KIND_COLOR[k], borderRadius: k === 'email' ? '2px' : '50%' }} />
            <span class="ms-muted">{KIND_LABEL[k]}</span>
          </span>
        ))}
        <span class="ms-faint">Shared nodes are what links the emails together.</span>
      </div>
    </div>
  );
}
