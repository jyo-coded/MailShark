// Investigation graph page: filters (left), canvas with search and tools (centre), inspector (right).
// Every node and edge comes from stored analysis and correlation results; when the server reduces a
// large graph it says what it hid and why, and double-clicking a node expands its neighbourhood.
import type { ComponentChildren } from 'preact';
import { useEffect, useRef, useState } from 'preact/hooks';
import { Crosshair, Expand, Eye, Maximize2, Minus, Pause, Pin, Play, Plus, RotateCcw, Search, Tag, TriangleAlert, X } from 'lucide-preact';
import { api } from '../lib/api';
import { useDebounced } from '../lib/hooks';
import { href, navigate, setQuery, useRoute } from '../lib/router';
import { toastError, usePref } from '../lib/store';
import { fmtNum, human, pct, short } from '../lib/format';
import type { GEdge, GNode, GraphPayload, NodeKind, SourceInfo } from '../lib/types';
import { useCase } from '../components/Shell';
import { Badge, ClassBadge, KV, Loading, Sev, Spinner, Time } from '../components/ui';
import { EDGE_LABEL, GraphView, KIND_META, type Selection } from '../graph/view';

const ALL_KINDS = Object.keys(KIND_META) as NodeKind[];
const DEFAULT_KINDS: NodeKind[] = ['message', 'cluster', 'external', 'sender', 'reply-to', 'domain', 'ip', 'attachment', 'phone', 'wallet'];
const CLASSES = ['malicious', 'suspicious', 'inconclusive', 'benign', 'failed'];
const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info', 'none'];

interface Filters {
  kinds: NodeKind[];
  classes: string[];
  severities: string[];
  sources: string[];
  minEdge: number;
  similarity: boolean;
  sharedOnly: boolean;
  limit: number;
  from: string;
  to: string;
}

const DEFAULT_FILTERS: Filters = { kinds: DEFAULT_KINDS, classes: [], severities: [], sources: [], minEdge: 0.6, similarity: true, sharedOnly: false, limit: 600, from: '', to: '' };

function swatch(kind: NodeKind): { background: string } {
  const c = KIND_META[kind].color;
  return { background: c.startsWith('--') ? `var(${c})` : c };
}

function mergePayload(a: GraphPayload, b: GraphPayload): GraphPayload {
  const nodes = new Map(a.nodes.map((n) => [n.id, n]));
  for (const n of b.nodes) if (!nodes.has(n.id)) nodes.set(n.id, n);
  const edges = new Map(a.edges.map((e) => [e.id, e]));
  for (const e of b.edges) if (!edges.has(e.id)) edges.set(e.id, e);
  return { ...a, nodes: [...nodes.values()], edges: [...edges.values()] };
}

export function Graph() {
  const { c } = useCase();
  const { query } = useRoute();
  const focus = query.get('focus') ?? '';
  const cluster = query.get('cluster');
  const [stored, setStored] = usePref<Filters>(`graph.filters`, DEFAULT_FILTERS);
  const f = { ...DEFAULT_FILTERS, ...stored };
  const setF = (patch: Partial<Filters>): void => setStored({ ...f, ...patch });
  const [search, setSearch] = useState('');
  const q = useDebounced(search, 400);
  const [data, setData] = useState<GraphPayload | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<string[]>([]);
  const [sel, setSel] = useState<Selection>(null);
  const [labels, setLabels] = usePref<'auto' | 'all' | 'none'>('graph.labels', 'auto');
  const [running, setRunning] = useState(true);
  const [, setTick] = useState(0);
  const canvas = useRef<HTMLCanvasElement>(null);
  const view = useRef<GraphView | null>(null);
  const [intelSources, setIntelSources] = useState<string[]>([]);
  const [reloadKey, setReloadKey] = useState(0);
  const applied = useRef<Set<string>>(new Set());
  const expandedRef = useRef<string[]>([]);
  expandedRef.current = expanded;

  useEffect(() => {
    void api
      .get<{ sources: SourceInfo[] }>('/api/intel/sources')
      .then((r) => setIntelSources(r.sources.filter((s) => s.kind !== 'enrichment' && (s.recordCount > 0 || s.kind === 'lookup')).map((s) => s.id)))
      .catch(() => undefined);
  }, []);

  const params = (extra: Record<string, string | number | boolean | null> = {}): Record<string, string | number | boolean | null | string[]> => ({
    types: f.kinds,
    classes: f.classes,
    severities: f.severities,
    sources: f.sources,
    minEdge: f.minEdge,
    similarity: f.similarity ? null : '0',
    minDegree: f.sharedOnly ? 2 : null,
    limit: f.limit,
    from: f.from ? Date.parse(`${f.from}T00:00:00Z`) : null,
    to: f.to ? Date.parse(`${f.to}T23:59:59Z`) : null,
    cluster,
    focus: focus || null,
    q: q || null,
    ...extra,
  });

  // Base load (filters, focus, search); expansions made so far are re-applied on top.
  useEffect(() => {
    const ac = new AbortController();
    setLoading(true);
    setError(null);
    api
      .get<GraphPayload>(`/api/cases/${c.id}/graph`, params() as never, ac.signal)
      .then(async (base) => {
        let merged = base;
        const ids = [...expandedRef.current];
        for (const id of ids) merged = mergePayload(merged, await api.get<GraphPayload>(`/api/cases/${c.id}/graph`, params({ focus: id, depth: 1, q: null, cluster: null }) as never, ac.signal));
        if (ac.signal.aborted) return;
        applied.current = new Set(ids);
        setData(merged);
      })
      .catch((e: unknown) => {
        if ((e as Error).name !== 'AbortError') setError(e instanceof Error ? e.message : String(e));
      })
      .finally(() => !ac.signal.aborted && setLoading(false));
    return () => ac.abort();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [c.id, JSON.stringify(f), focus, cluster, q, c.correlatedAt, reloadKey]);

  // Incremental expansion: fetch only the newly expanded node's neighbourhood and merge it in.
  useEffect(() => {
    const todo = expanded.filter((id) => !applied.current.has(id));
    if (!todo.length) return;
    let alive = true;
    setLoading(true);
    void (async () => {
      try {
        for (const id of todo) {
          const more = await api.get<GraphPayload>(`/api/cases/${c.id}/graph`, params({ focus: id, depth: 1, q: null, cluster: null }) as never);
          if (!alive) return;
          applied.current.add(id);
          setData((d) => (d ? mergePayload(d, more) : more));
        }
      } catch (e) {
        toastError(e);
      } finally {
        if (alive) setLoading(false);
      }
    })();
    return () => {
      alive = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [expanded.join(',')]);

  useEffect(() => {
    if (!canvas.current) return;
    const v = new GraphView(canvas.current, {
      onSelect: (s) => setSel(s),
      onExpand: (id) => setExpanded((x) => (x.includes(id) ? x : [...x, id])),
      onHover: () => undefined,
    });
    view.current = v;
    const mo = new MutationObserver(() => v.refreshTheme());
    mo.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });
    return () => {
      mo.disconnect();
      v.destroy();
      view.current = null;
    };
  }, []);

  useEffect(() => {
    if (!data || !view.current) return;
    view.current.setData(data.nodes, data.edges);
    setRunning(true);
    if (focus && data.nodes.some((n) => n.id === focus.split(',')[0])) {
      const id = focus.split(',')[0] as string;
      setTimeout(() => {
        view.current?.select({ type: 'node', id });
        view.current?.centerOn(id);
      }, 900);
    }
  }, [data]);

  useEffect(() => view.current?.setLabels(labels), [labels]);

  // Highlight search matches within the loaded graph (the server search already narrowed it).
  useEffect(() => {
    if (!view.current || !data) return;
    if (!q) view.current.setHighlight(null);
    else {
      const needle = q.toLowerCase();
      view.current.setHighlight(new Set(data.nodes.filter((n) => n.label.toLowerCase().includes(needle) || (n.sublabel ?? '').toLowerCase().includes(needle)).map((n) => n.id)));
    }
  }, [q, data]);

  const kindsAvailable = data?.kindsAvailable ?? {};
  const hiddenTotal = Object.values(data?.hidden ?? {}).reduce((s, n) => s + (n ?? 0), 0);
  const selNode = sel?.type === 'node' ? view.current?.node(sel.id) ?? null : null;
  const selEdge = sel?.type === 'edge' ? view.current?.edge(sel.id) ?? null : null;
  const toggle = <T,>(arr: T[], v: T): T[] => (arr.includes(v) ? arr.filter((x) => x !== v) : [...arr, v]);

  return (
    <div class="graph-page" data-inspector={sel ? undefined : 'closed'}>
      <aside class="graph-filters" aria-label="Graph filters">
        <div class="f-group">
          <div class="f-title">
            <span>Entities</span>
            <button class="btn btn-ghost btn-sm" style={{ height: '18px', padding: '0 4px' }} onClick={() => setF({ kinds: DEFAULT_KINDS })}>
              default
            </button>
          </div>
          {ALL_KINDS.map((k) => (
            <button class="kind-toggle" aria-pressed={f.kinds.includes(k)} onClick={() => setF({ kinds: toggle(f.kinds, k) })}>
              <span class="box" />
              <span class="swatch" data-shape={KIND_META[k].shape} style={swatch(k)} />
              <span class="trunc">{KIND_META[k].label}</span>
              <span class="n">{kindsAvailable[k] !== undefined ? fmtNum(kindsAvailable[k] ?? 0) : ''}</span>
            </button>
          ))}
        </div>
        <div class="f-group">
          <div class="f-title">Message class</div>
          {CLASSES.map((cl) => (
            <label class="check small">
              <input type="checkbox" checked={f.classes.length === 0 || f.classes.includes(cl)} onChange={() => setF({ classes: f.classes.length === 0 ? CLASSES.filter((x) => x !== cl) : toggle(f.classes, cl).length === CLASSES.length ? [] : toggle(f.classes, cl) })} />
              <ClassBadge c={cl} />
            </label>
          ))}
        </div>
        <div class="f-group">
          <div class="f-title">Severity</div>
          <div class="row wrap" style={{ gap: '4px' }}>
            {SEVERITIES.map((s) => (
              <button class="chip" style={{ height: '22px', padding: '0 8px' }} aria-pressed={f.severities.includes(s)} onClick={() => setF({ severities: toggle(f.severities, s) })}>
                <Sev s={s} />
              </button>
            ))}
          </div>
          <span class="xs faint">{f.severities.length ? 'Only messages with these severities.' : 'All severities.'}</span>
        </div>
        <div class="f-group">
          <div class="f-title">Relationships</div>
          <label class="check small">
            <input type="checkbox" checked={f.similarity} onChange={(e) => setF({ similarity: (e.target as HTMLInputElement).checked })} /> Message-to-message relations
          </label>
          <label class="small muted" for="minEdge">
            Minimum relationship score: <b class="mono">{f.minEdge.toFixed(2)}</b>
          </label>
          <input id="minEdge" class="range" type="range" min="0.6" max="1" step="0.05" value={f.minEdge} onChange={(e) => setF({ minEdge: Number((e.target as HTMLInputElement).value) })} />
          <label class="check small">
            <input type="checkbox" checked={f.sharedOnly} onChange={(e) => setF({ sharedOnly: (e.target as HTMLInputElement).checked })} /> Shared indicators only
          </label>
        </div>
        <div class="f-group">
          <div class="f-title">Intelligence source</div>
          {intelSources.length === 0 ? (
            <span class="xs faint">No synchronised sources.</span>
          ) : (
            intelSources.map((s) => (
              <label class="check small">
                <input type="checkbox" checked={f.sources.includes(s)} onChange={() => setF({ sources: toggle(f.sources, s) })} /> {s}
              </label>
            ))
          )}
          <span class="xs faint">{f.sources.length ? 'Indicators and external events from these sources only.' : 'No source filter.'}</span>
        </div>
        <div class="f-group">
          <div class="f-title">Time (Date header, UTC)</div>
          <input class="input" type="date" value={f.from} onInput={(e) => setF({ from: (e.target as HTMLInputElement).value })} aria-label="From date" />
          <input class="input" type="date" value={f.to} onInput={(e) => setF({ to: (e.target as HTMLInputElement).value })} aria-label="To date" />
        </div>
        <div class="f-group">
          <div class="f-title">Size</div>
          <select class="select" value={f.limit} onChange={(e) => setF({ limit: Number((e.target as HTMLSelectElement).value) })}>
            {[200, 600, 1200, 3000].map((n) => (
              <option value={n}>Up to {fmtNum(n)} entities</option>
            ))}
          </select>
          <button class="btn btn-sm" onClick={() => setStored(DEFAULT_FILTERS)}>
            Reset filters
          </button>
        </div>
      </aside>

      <div class="graph-stage">
        <canvas ref={canvas} aria-label="Investigation graph. Use the inspector panel for details of the selected entity." />
        <div class="graph-hud top-left">
          <div class="hud-panel search">
            <Search />
            <input placeholder="Search entities (subject, address, domain, hash…)" value={search} onInput={(e) => setSearch((e.target as HTMLInputElement).value)} aria-label="Search the graph" />
            {search && (
              <button class="btn btn-ghost btn-sm btn-icon" aria-label="Clear search" onClick={() => setSearch('')}>
                <X />
              </button>
            )}
          </div>
          {(focus || cluster || expanded.length > 0) && (
            <div class="hud-panel stats row" style={{ gap: '6px' }}>
              {focus && <span>focus: {focus.split(',').length}</span>}
              {cluster && <span>cluster: {short(cluster, 16)}</span>}
              {expanded.length > 0 && <span>expanded: {expanded.length}</span>}
              <button
                class="btn btn-ghost btn-sm"
                style={{ height: '20px' }}
                onClick={() => {
                  setExpanded([]);
                  expandedRef.current = [];
                  setQuery({ focus: null, cluster: null });
                  setReloadKey((k) => k + 1);
                }}
              >
                show all
              </button>
            </div>
          )}
          <div class="hud-panel stats">
            {loading ? <Spinner /> : data ? `${fmtNum(data.nodes.length)} entities · ${fmtNum(data.edges.length)} links${data.totals.nodes > data.nodes.length ? ` (of ${fmtNum(data.totals.nodes)})` : ''}` : '…'}
          </div>
          {data && hiddenTotal > 0 && (
            <div class="hud-panel hidden-banner" title={data.hiddenReason ?? ''}>
              <TriangleAlert />
              <span>
                {fmtNum(hiddenTotal)} lower-priority entities not drawn ({Object.entries(data.hidden).map(([k, n]) => `${n} ${KIND_META[k as NodeKind]?.label.toLowerCase() ?? k}`).join(', ')}). Narrow the filters, search, or double-click a node to expand it.
              </span>
            </div>
          )}
        </div>
        {error && (
          <div class="graph-empty">
            <div class="hud-panel" style={{ padding: '12px 16px', maxWidth: '420px' }}>
              {error}
            </div>
          </div>
        )}
        {!error && data && data.nodes.length === 0 && !loading && (
          <div class="graph-empty">
            <div class="hud-panel" style={{ padding: '12px 16px', maxWidth: '420px', textAlign: 'center' }}>
              <b>Nothing to draw.</b>
              <div class="small muted">No analysed message matches the filters{q ? ' and the search' : ''}.</div>
            </div>
          </div>
        )}
        {!data && !error && (
          <div class="graph-empty">
            <Loading label="Building the graph…" />
          </div>
        )}
        <div class="graph-hud bottom-right">
          <div class="hud-panel hud-tools">
            <button class="btn" title="Zoom in" aria-label="Zoom in" onClick={() => view.current?.zoomBy(1.3)}>
              <Plus />
            </button>
            <button class="btn" title="Zoom out" aria-label="Zoom out" onClick={() => view.current?.zoomBy(1 / 1.3)}>
              <Minus />
            </button>
            <button class="btn" title="Fit to screen" aria-label="Fit to screen" onClick={() => view.current?.fit()}>
              <Maximize2 />
            </button>
            <button class="btn" title={running ? 'Freeze layout' : 'Resume layout'} aria-label={running ? 'Freeze layout' : 'Resume layout'} aria-pressed={!running} onClick={() => setRunning(view.current?.toggleRunning() ?? true)}>
              {running ? <Pause /> : <Play />}
            </button>
            <button class="btn" title={`Labels: ${labels}`} aria-label="Cycle labels" aria-pressed={labels !== 'auto'} onClick={() => setLabels(labels === 'auto' ? 'all' : labels === 'all' ? 'none' : 'auto')}>
              <Tag />
            </button>
            <button
              class="btn"
              title="Reset layout (unpin all, clear expansions)"
              aria-label="Reset layout"
              onClick={() => {
                const hadExpansions = expanded.length > 0;
                setExpanded([]);
                if (hadExpansions) {
                  expandedRef.current = [];
                  setReloadKey((k) => k + 1);
                }
                view.current?.resetLayout();
                view.current?.select(null);
              }}
            >
              <RotateCcw />
            </button>
          </div>
        </div>
        <div class="graph-hud bottom-left">
          <div class="hud-panel hud-legend">
            <span>
              <i style={{ background: 'var(--malicious)', borderRadius: '2px' }} /> malicious
            </span>
            <span>
              <i style={{ background: 'var(--suspicious)', borderRadius: '2px' }} /> suspicious
            </span>
            <span>
              <i style={{ background: 'var(--benign)', borderRadius: '2px' }} /> benign
            </span>
            <span>
              <i style={{ border: '1.5px solid var(--intel)', background: 'transparent' }} /> listed by intel
            </span>
            <span>
              <i class="line" style={{ borderTopColor: 'var(--malicious)' }} /> exact relation
            </span>
            <span>
              <i class="line dashed" style={{ borderTopColor: 'var(--suspicious)' }} /> probable
            </span>
            <span class="faint">drag to pin · double-click to expand · scroll to zoom</span>
          </div>
        </div>
      </div>

      {sel && (
        <aside class="graph-inspector" aria-label="Inspector">
          <div class="panel-head">
            <h3>Inspector</h3>
            <div class="actions">
              <button class="btn btn-ghost btn-sm btn-icon" aria-label="Close inspector" onClick={() => view.current?.select(null)}>
                <X />
              </button>
            </div>
          </div>
          <div class="ins-body">
            {selNode && (
              <NodeInspector
                n={selNode}
                caseId={c.id}
                neighbours={view.current?.neighbours(selNode.id) ?? []}
                pinned={!!selNode.pinnedByUser}
                onSelect={(s) => {
                  view.current?.select(s);
                  if (s?.type === 'node') view.current?.centerOn(s.id, false);
                }}
                onExpand={() => setExpanded((x) => (x.includes(selNode.id) ? x : [...x, selNode.id]))}
                onFocus={() => {
                  setExpanded([]);
                  expandedRef.current = [];
                  setQuery({ focus: selNode.id, cluster: null }, { replace: false });
                }}
                onUnpin={() => {
                  view.current?.unpin(selNode.id);
                  setTick((t) => t + 1);
                }}
                onCenter={() => view.current?.centerOn(selNode.id)}
              />
            )}
            {selEdge && <EdgeInspector e={selEdge as unknown as GEdge & { source: GNode; target: GNode }} onSelect={(s) => view.current?.select(s)} />}
            {!selNode && !selEdge && <span class="small faint">The selection is no longer in the graph.</span>}
          </div>
        </aside>
      )}
    </div>
  );
}

function NodeInspector({ n, caseId, neighbours, pinned, onSelect, onExpand, onFocus, onUnpin, onCenter }: { n: GNode; caseId: string; neighbours: { node: GNode; edge: { id: string; kind: GEdge['kind']; tier?: string; weight: number } }[]; pinned: boolean; onSelect: (s: Selection) => void; onExpand: () => void; onFocus: () => void; onUnpin: () => void; onCenter: () => void }) {
  const meta = KIND_META[n.kind];
  const open = (): void => {
    if (n.kind === 'message') navigate(href(`/cases/${caseId}/messages`, { m: n.ref }));
    else if (n.kind === 'cluster') navigate(href(`/cases/${caseId}/campaigns`, { c: n.ref }));
    else if (n.kind === 'external') navigate(href(`/cases/${caseId}/campaigns`, { tab: 'external' }));
    else navigate(href(`/cases/${caseId}/indicators`, { i: n.ref }));
  };
  const groups = new Map<string, typeof neighbours>();
  for (const x of neighbours) (groups.get(x.edge.kind) ?? groups.set(x.edge.kind, []).get(x.edge.kind))?.push(x);
  return (
    <>
      <div>
        <span class="ins-kind">
          <i style={swatch(n.kind)} /> {meta.label}
        </span>
        <div class="ins-title mono" style={{ fontFamily: n.kind === 'message' || n.kind === 'cluster' || n.kind === 'external' ? 'var(--font)' : undefined }}>
          {n.label}
        </div>
        {n.sublabel && <div class="small muted break">{n.sublabel}</div>}
      </div>
      <div class="row wrap" style={{ gap: '6px' }}>
        <button class="btn btn-sm btn-primary" onClick={open}>
          <Eye /> Open
        </button>
        <button class="btn btn-sm" onClick={onExpand} title="Add this entity's direct neighbours (including ones hidden by the size limit)">
          <Expand /> Expand
        </button>
        <button class="btn btn-sm" onClick={onFocus} title="Show only this entity's neighbourhood">
          <Crosshair /> Focus
        </button>
        <button class="btn btn-sm btn-ghost" onClick={onCenter}>
          Centre
        </button>
        {pinned && (
          <button class="btn btn-sm btn-ghost" onClick={onUnpin}>
            <Pin /> Unpin
          </button>
        )}
      </div>
      <KV
        rows={[
          ...(n.kind === 'message'
            ? ([
                ['Class', <ClassBadge c={n.cls} />],
                ['Severity', <Sev s={n.severity} />],
                ['Score', n.score ?? '—'],
                ['Sent', <Time ms={n.time} />],
              ] as [string, ComponentChildren][])
            : []),
          ...(n.kind === 'cluster' ? ([['Verdict', String(n.data?.['verdict'] ?? '')], ['Members', String(n.data?.['size'] ?? '')], ['Confidence', String(n.data?.['confidence'] ?? '')], ['Cohesion', pct(Number(n.data?.['cohesion'] ?? 0))]] as [string, string][]) : []),
          ...(n.kind === 'external' ? ([['Source', String(n.data?.['source'] ?? '')], ['Assessment', human(String(n.data?.['assessment'] ?? ''))], ['Confidence', String(n.data?.['confidence'] ?? '')], ['Event date', <Time ms={n.time} />]] as [string, ComponentChildren][]) : []),
          ...(n.intel ? ([['Intelligence', <span style={{ color: 'var(--intel)' }}>{`${n.intel.sources.join(', ')}${n.intel.threats.length ? ` · ${n.intel.threats.join(', ')}` : ''} · strength ${n.intel.strongest.toFixed(2)}`}</span>]] as [string, ComponentChildren][]) : []),
          ...(n.suspicious ? ([['Engine', 'risky in context (not an intelligence verdict)']] as [string, string][]) : []),
          ['Connections', String(neighbours.length)],
        ]}
      />
      <div class="ins-neighbours">
        {[...groups.entries()].map(([kind, list]) => (
          <>
            <div class="section-title" style={{ marginTop: '8px' }}>
              {EDGE_LABEL[kind as GEdge['kind']] ?? kind} ({list.length})
            </div>
            {list.slice(0, 60).map((x) => (
              <button onClick={() => onSelect({ type: 'node', id: x.node.id })} onDblClick={() => onSelect({ type: 'edge', id: x.edge.id })} title="Click: select entity · double-click: inspect the link">
                <i style={x.node.kind === 'message' ? { background: `var(--${x.node.cls ?? 'inconclusive'})`, borderRadius: '2px' } : swatch(x.node.kind)} />
                <span class="trunc">{x.node.label}</span>
                <span class="rel">{x.edge.tier ?? (x.edge.kind === 'similar-to' ? x.edge.weight.toFixed(2) : '')}</span>
              </button>
            ))}
            {list.length > 60 && <span class="xs faint">… {list.length - 60} more</span>}
          </>
        ))}
      </div>
    </>
  );
}

function EdgeInspector({ e, onSelect }: { e: GEdge & { source: GNode; target: GNode }; onSelect: (s: Selection) => void }) {
  return (
    <>
      <div>
        <span class="ins-kind">Link · {EDGE_LABEL[e.kind] ?? e.kind}</span>
        <div class="ins-title">{e.kind === 'similar-to' ? `${e.tier === 'exact' ? 'Exact' : 'Probable'} relationship · ${e.weight.toFixed(2)}` : EDGE_LABEL[e.kind]}</div>
      </div>
      <div class="col" style={{ gap: '4px' }}>
        <button class="btn btn-sm" style={{ justifyContent: 'flex-start' }} onClick={() => onSelect({ type: 'node', id: e.source.id })}>
          <span class="trunc">{e.source.label}</span>
        </button>
        <span class="faint small center">{EDGE_LABEL[e.kind] ?? e.kind} ↓</span>
        <button class="btn btn-sm" style={{ justifyContent: 'flex-start' }} onClick={() => onSelect({ type: 'node', id: e.target.id })}>
          <span class="trunc">{e.target.label}</span>
        </button>
      </div>
      <div>
        <div class="section-title">Evidence for this link</div>
        {e.evidence.slice(0, 20).map((ev) => (
          <div class="panel" style={{ padding: '8px 10px', marginBottom: '6px' }}>
            {e.kind === 'similar-to' ? (
              <>
                {ev['hardLink'] ? <div class="small">Hard link: {String(ev['hardLink'])}</div> : null}
                <div class="row wrap" style={{ gap: '3px', marginTop: '4px' }}>
                  {((ev['shared'] as { family: string; value: string; strength: number }[] | undefined) ?? []).map((s) => (
                    <Badge outline title={`strength ${s.strength.toFixed(2)}`}>
                      {s.family}: {short(s.value, 30)}
                    </Badge>
                  ))}
                </div>
                <div class="xs faint" style={{ marginTop: '4px' }}>
                  {Object.entries((ev['layers'] as Record<string, number | null> | undefined) ?? {})
                    .filter(([, v]) => v !== null)
                    .map(([k, v]) => `${k} ${pct(v as number)}`)
                    .join(' · ')}
                </div>
              </>
            ) : (
              <table class="ev-table">
                <tbody>
                  {Object.entries(ev)
                    .filter(([, v]) => v !== null && v !== undefined && v !== '')
                    .map(([k, v]) => (
                      <tr>
                        <td>{human(k)}</td>
                        <td class="mono break">{typeof v === 'number' ? (Number.isInteger(v) ? String(v) : v.toFixed(2)) : String(v)}</td>
                      </tr>
                    ))}
                </tbody>
              </table>
            )}
          </div>
        ))}
        {e.evidence.length > 20 && <span class="xs faint">… {e.evidence.length - 20} more observations</span>}
      </div>
    </>
  );
}
