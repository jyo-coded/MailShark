// Canvas investigation graph: force layout (d3-force), quadtree hit testing (d3-quadtree), zoom/pan,
// drag-to-pin, node and edge selection, incremental merges that keep the existing layout.
// Rendering is on demand (only while the simulation moves or the view changes).
import { forceCollide, forceLink, forceManyBody, forceSimulation, forceX, forceY, type Simulation, type SimulationLinkDatum, type SimulationNodeDatum } from 'd3-force';
import { quadtree, type Quadtree } from 'd3-quadtree';
import type { GEdge, GNode, NodeKind } from '../lib/types';

export interface VNode extends SimulationNodeDatum, GNode {
  r: number;
  /** Dropped here by the analyst: stays fixed until released. */
  pinnedByUser?: boolean;
}
export interface VEdge extends SimulationLinkDatum<VNode>, Omit<GEdge, 'source' | 'target'> {
  source: VNode;
  target: VNode;
}

export type Selection = { type: 'node'; id: string } | { type: 'edge'; id: string } | null;

export const KIND_META: Record<NodeKind, { label: string; color: string; shape: 'square' | 'circle' | 'hex' | 'diamond' }> = {
  message: { label: 'Message', color: '--inconclusive', shape: 'square' },
  cluster: { label: 'Local cluster', color: '--accent', shape: 'hex' },
  external: { label: 'External campaign', color: '--intel', shape: 'diamond' },
  sender: { label: 'Sender address', color: '#a78bfa', shape: 'circle' },
  'sender-domain': { label: 'Sender domain', color: '#8b8cf6', shape: 'circle' },
  'reply-to': { label: 'Reply-To', color: '#f472b6', shape: 'circle' },
  domain: { label: 'Link domain', color: '#38bdf8', shape: 'circle' },
  hostname: { label: 'Link host', color: '#22d3ee', shape: 'circle' },
  url: { label: 'URL', color: '#5eead4', shape: 'circle' },
  ip: { label: 'IP address', color: '#60a5fa', shape: 'circle' },
  attachment: { label: 'Attachment', color: '#fb923c', shape: 'circle' },
  phone: { label: 'Phone number', color: '#facc15', shape: 'circle' },
  wallet: { label: 'Crypto wallet', color: '#fbbf24', shape: 'circle' },
  recipient: { label: 'Recipient', color: '#94a3b8', shape: 'circle' },
};

export const EDGE_LABEL: Record<GEdge['kind'], string> = {
  'sent-by': 'sent by',
  'sender-domain': 'sender domain',
  'replies-to': 'replies to',
  'links-to': 'links to',
  'sent-from': 'sent from IP',
  'composed-from': 'composed from client IP',
  carries: 'carries attachment',
  mentions: 'mentions',
  'pays-to': 'pays to',
  'addressed-to': 'addressed to',
  'submitted-by': 'submitted by account',
  'bounces-to': 'bounces to',
  'member-of': 'member of cluster',
  'similar-to': 'related message',
  'reported-in': 'listed in external event',
  matches: 'matches external event',
};

interface Palette {
  bg: string;
  edge: string;
  edgeStrong: string;
  label: string;
  text3: string;
  accent: string;
  intel: string;
  cls: Record<string, string>;
  kind: Record<string, string>;
  panel: string;
}

function readPalette(el: HTMLElement): Palette {
  const cs = getComputedStyle(el);
  const v = (n: string): string => cs.getPropertyValue(n).trim() || '#888';
  const kind: Record<string, string> = {};
  for (const [k, m] of Object.entries(KIND_META)) kind[k] = m.color.startsWith('--') ? v(m.color) : m.color;
  return {
    bg: v('--g-bg'),
    edge: v('--g-edge'),
    edgeStrong: v('--g-edge-strong'),
    label: v('--g-label'),
    text3: v('--text-3'),
    accent: v('--accent'),
    intel: v('--intel'),
    panel: v('--panel'),
    cls: { malicious: v('--malicious'), suspicious: v('--suspicious'), inconclusive: v('--inconclusive'), benign: v('--benign'), failed: v('--failed') },
    kind,
  };
}

export function nodeColor(n: GNode, p: Palette): string {
  if (n.kind === 'message') return p.cls[n.cls ?? ''] ?? p.text3;
  if (n.kind === 'cluster') return n.cls === 'malicious' ? p.cls['malicious'] ?? p.accent : p.accent;
  return p.kind[n.kind] ?? p.text3;
}

function radius(n: GNode): number {
  if (n.kind === 'cluster') return 13 + Math.min(12, Math.sqrt(Number(n.data?.['size'] ?? 1)) * 2);
  if (n.kind === 'external') return 11;
  if (n.kind === 'message') return 6 + (n.cls === 'malicious' ? 2 : n.cls === 'suspicious' ? 1 : 0);
  return 4 + Math.min(7, Math.sqrt(n.degree) * 1.6);
}

export interface ViewCallbacks {
  onSelect: (s: Selection) => void;
  onExpand: (nodeId: string) => void;
  onHover: (id: string | null) => void;
}

export class GraphView {
  nodes: VNode[] = [];
  edges: VEdge[] = [];
  private byId = new Map<string, VNode>();
  private adj = new Map<string, Set<string>>();
  private sim: Simulation<VNode, VEdge>;
  private tree: Quadtree<VNode> | null = null;
  private ctx: CanvasRenderingContext2D;
  private palette: Palette;
  private t = { x: 0, y: 0, k: 1 };
  private w = 0;
  private h = 0;
  private dpr = 1;
  private dirty = true;
  private raf = 0;
  private ro: ResizeObserver;
  selection: Selection = null;
  private hover: string | null = null;
  private highlight: Set<string> | null = null;
  labels: 'auto' | 'all' | 'none' = 'auto';
  running = true;
  private drag: { node: VNode | null; startX: number; startY: number; moved: boolean; panX: number; panY: number; pointer: number } | null = null;
  private fitted = false;
  private interacted = false;

  constructor(
    private readonly canvas: HTMLCanvasElement,
    private readonly cb: ViewCallbacks,
  ) {
    this.ctx = canvas.getContext('2d') as CanvasRenderingContext2D;
    this.palette = readPalette(canvas);
    this.sim = forceSimulation<VNode, VEdge>([])
      .force('link', forceLink<VNode, VEdge>([]).id((d) => d.id).distance((e) => (e.kind === 'member-of' ? 60 : e.kind === 'similar-to' ? 70 + (1 - e.weight) * 80 : e.kind === 'reported-in' ? 90 : 46)).strength((e) => (e.kind === 'similar-to' ? 0.25 + e.weight * 0.4 : e.kind === 'member-of' ? 0.35 : 0.5)))
      .force('charge', forceManyBody<VNode>().strength((n) => (n.kind === 'cluster' ? -420 : n.kind === 'message' ? -110 : -70)).distanceMax(520).theta(0.9))
      .force('collide', forceCollide<VNode>().radius((n) => n.r + 3).iterations(1))
      .force('x', forceX<VNode>(0).strength(0.035))
      .force('y', forceY<VNode>(0).strength(0.035))
      .alphaDecay(0.03)
      .on('tick', () => {
        this.tree = null;
        this.dirty = true;
        // Frame the layout once it has roughly settled (the remaining motion is small).
        if (!this.fitted && this.sim.alpha() < 0.3) {
          this.fitted = true;
          this.fit(true);
        }
      })
      .on('end', () => {
        // Re-frame the settled layout unless the analyst has already moved the view.
        if (!this.interacted) this.fit(true);
      });
    this.ro = new ResizeObserver(() => this.resize());
    this.ro.observe(canvas);
    this.resize();
    this.bind();
    const loop = (): void => {
      if (this.dirty) {
        this.dirty = false;
        this.draw();
      }
      this.raf = requestAnimationFrame(loop);
    };
    this.raf = requestAnimationFrame(loop);
  }

  destroy(): void {
    cancelAnimationFrame(this.raf);
    this.ro.disconnect();
    this.sim.stop();
    this.unbind();
  }

  refreshTheme(): void {
    this.palette = readPalette(this.canvas);
    this.dirty = true;
  }

  /** Replaces the data. Nodes already on screen keep their positions; new nodes start near a neighbour. */
  setData(nodes: GNode[], edges: GEdge[]): void {
    const old = this.byId;
    this.byId = new Map();
    const vn: VNode[] = nodes.map((n) => {
      const prev = old.get(n.id);
      const v: VNode = Object.assign(prev ?? ({} as VNode), n, { r: radius(n) });
      this.byId.set(n.id, v);
      return v;
    });
    this.adj = new Map();
    const ve: VEdge[] = [];
    for (const e of edges) {
      const s = this.byId.get(e.source);
      const t = this.byId.get(e.target);
      if (!s || !t) continue;
      ve.push({ ...e, source: s, target: t });
      (this.adj.get(s.id) ?? this.adj.set(s.id, new Set()).get(s.id))?.add(t.id);
      (this.adj.get(t.id) ?? this.adj.set(t.id, new Set()).get(t.id))?.add(s.id);
    }
    for (const n of vn) {
      if (n.x !== undefined) continue;
      const nb = [...(this.adj.get(n.id) ?? [])].map((id) => this.byId.get(id)).find((x) => x && x.x !== undefined);
      const a = Math.random() * Math.PI * 2;
      const d = nb ? 30 + Math.random() * 30 : 200 * Math.sqrt(Math.random());
      n.x = (nb?.x ?? 0) + Math.cos(a) * d;
      n.y = (nb?.y ?? 0) + Math.sin(a) * d;
    }
    this.nodes = vn;
    this.edges = ve;
    if (this.selection?.type === 'node' && !this.byId.has(this.selection.id)) this.select(null);
    if (this.selection?.type === 'edge' && !ve.some((e) => e.id === this.selection?.id)) this.select(null);
    this.sim.nodes(vn);
    (this.sim.force('link') as ReturnType<typeof forceLink<VNode, VEdge>>).links(ve);
    const fresh = vn.filter((n) => !old.has(n.id)).length;
    if (!old.size) {
      this.fitted = false;
      this.interacted = false;
    }
    this.sim.alpha(old.size ? Math.min(0.6, 0.15 + fresh / Math.max(1, vn.length)) : 1).restart();
    this.running = true;
    this.tree = null;
    this.dirty = true;
  }

  node(id: string): VNode | undefined {
    return this.byId.get(id);
  }

  neighbours(id: string): { node: VNode; edge: VEdge }[] {
    const out: { node: VNode; edge: VEdge }[] = [];
    for (const e of this.edges) {
      if (e.source.id === id) out.push({ node: e.target, edge: e });
      else if (e.target.id === id) out.push({ node: e.source, edge: e });
    }
    return out;
  }

  edge(id: string): VEdge | undefined {
    return this.edges.find((e) => e.id === id);
  }

  select(s: Selection, notify = true): void {
    this.selection = s;
    this.dirty = true;
    if (notify) this.cb.onSelect(s);
  }

  setHighlight(ids: Set<string> | null): void {
    this.highlight = ids && ids.size ? ids : null;
    this.dirty = true;
  }

  setLabels(mode: 'auto' | 'all' | 'none'): void {
    this.labels = mode;
    this.dirty = true;
  }

  toggleRunning(): boolean {
    this.running = !this.running;
    if (this.running) this.sim.alpha(Math.max(this.sim.alpha(), 0.3)).restart();
    else this.sim.stop();
    return this.running;
  }

  /** Unpins every node and re-runs the layout from the current positions. */
  resetLayout(): void {
    for (const n of this.nodes) {
      n.fx = null;
      n.fy = null;
    }
    this.fitted = false;
    this.running = true;
    this.sim.alpha(1).restart();
  }

  zoomBy(f: number, cx = this.w / 2, cy = this.h / 2): void {
    const k = Math.min(8, Math.max(0.05, this.t.k * f));
    const r = k / this.t.k;
    this.t.x = cx - (cx - this.t.x) * r;
    this.t.y = cy - (cy - this.t.y) * r;
    this.t.k = k;
    this.dirty = true;
  }

  fit(animate = true): void {
    if (!this.nodes.length || !this.w) return;
    let x0 = Infinity;
    let y0 = Infinity;
    let x1 = -Infinity;
    let y1 = -Infinity;
    for (const n of this.nodes) {
      x0 = Math.min(x0, (n.x ?? 0) - n.r);
      y0 = Math.min(y0, (n.y ?? 0) - n.r);
      x1 = Math.max(x1, (n.x ?? 0) + n.r);
      y1 = Math.max(y1, (n.y ?? 0) + n.r);
    }
    const pad = 60;
    const k = Math.min(2.5, Math.max(0.05, Math.min((this.w - pad * 2) / Math.max(1, x1 - x0), (this.h - pad * 2) / Math.max(1, y1 - y0))));
    this.animateTo({ k, x: this.w / 2 - ((x0 + x1) / 2) * k, y: this.h / 2 - ((y0 + y1) / 2) * k }, animate);
  }

  centerOn(id: string, zoom = true): void {
    const n = this.byId.get(id);
    if (!n || n.x === undefined || n.y === undefined) return;
    const k = zoom ? Math.max(this.t.k, 1.4) : this.t.k;
    this.animateTo({ k, x: this.w / 2 - n.x * k, y: this.h / 2 - n.y * k }, true);
  }

  private animateTo(to: { x: number; y: number; k: number }, animate: boolean): void {
    if (!animate || window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
      this.t = to;
      this.dirty = true;
      return;
    }
    const from = { ...this.t };
    const start = performance.now();
    const step = (now: number): void => {
      const p = Math.min(1, (now - start) / 380);
      const e = 1 - Math.pow(1 - p, 3);
      this.t = { x: from.x + (to.x - from.x) * e, y: from.y + (to.y - from.y) * e, k: from.k + (to.k - from.k) * e };
      this.dirty = true;
      if (p < 1) requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
  }

  // ── Geometry & hit testing ──

  private resize(): void {
    const r = this.canvas.getBoundingClientRect();
    this.dpr = Math.min(2, window.devicePixelRatio || 1);
    const first = !this.w;
    // Keep the world point at the centre of the view where it was (e.g. when the inspector opens).
    if (!first) {
      this.t.x += (r.width - this.w) / 2;
      this.t.y += (r.height - this.h) / 2;
    }
    this.w = r.width;
    this.h = r.height;
    this.canvas.width = Math.max(1, Math.round(r.width * this.dpr));
    this.canvas.height = Math.max(1, Math.round(r.height * this.dpr));
    if (first) this.t = { x: this.w / 2, y: this.h / 2, k: 1 };
    this.dirty = true;
  }

  private toWorld(px: number, py: number): [number, number] {
    return [(px - this.t.x) / this.t.k, (py - this.t.y) / this.t.k];
  }

  private nodeAt(px: number, py: number): VNode | null {
    if (!this.tree) this.tree = quadtree<VNode>().x((d) => d.x ?? 0).y((d) => d.y ?? 0).addAll(this.nodes);
    const [x, y] = this.toWorld(px, py);
    const hit = this.tree.find(x, y, 30 / this.t.k + 14);
    if (!hit) return null;
    const d = Math.hypot((hit.x ?? 0) - x, (hit.y ?? 0) - y);
    return d <= hit.r + 4 / this.t.k ? hit : null;
  }

  private edgeAt(px: number, py: number): VEdge | null {
    const [x, y] = this.toWorld(px, py);
    const tol = 5 / this.t.k;
    let best: VEdge | null = null;
    let bestD = tol;
    for (const e of this.edges) {
      const ax = e.source.x ?? 0;
      const ay = e.source.y ?? 0;
      const bx = e.target.x ?? 0;
      const by = e.target.y ?? 0;
      const dx = bx - ax;
      const dy = by - ay;
      const len = dx * dx + dy * dy;
      const t = len ? Math.max(0, Math.min(1, ((x - ax) * dx + (y - ay) * dy) / len)) : 0;
      const d = Math.hypot(x - (ax + t * dx), y - (ay + t * dy));
      if (d < bestD) {
        bestD = d;
        best = e;
      }
    }
    return best;
  }

  // ── Input ──

  private handlers: [string, EventListener][] = [];

  private bind(): void {
    const c = this.canvas;
    const pos = (e: PointerEvent | WheelEvent | MouseEvent): [number, number] => {
      const r = c.getBoundingClientRect();
      return [e.clientX - r.left, e.clientY - r.top];
    };
    const down = (ev: Event): void => {
      const e = ev as PointerEvent;
      if (e.button !== 0) return;
      this.interacted = true;
      const [px, py] = pos(e);
      const n = this.nodeAt(px, py);
      this.drag = { node: n, startX: px, startY: py, moved: false, panX: this.t.x, panY: this.t.y, pointer: e.pointerId };
      c.setPointerCapture(e.pointerId);
      if (n) {
        n.fx = n.x;
        n.fy = n.y;
      }
      c.dataset['cursor'] = 'grabbing';
    };
    const move = (ev: Event): void => {
      const e = ev as PointerEvent;
      const [px, py] = pos(e);
      const d = this.drag;
      if (d && d.pointer === e.pointerId) {
        if (!d.moved && Math.hypot(px - d.startX, py - d.startY) > 3) d.moved = true;
        if (!d.moved) return;
        if (d.node) {
          const [x, y] = this.toWorld(px, py);
          d.node.fx = x;
          d.node.fy = y;
          if (this.running) this.sim.alphaTarget(0.25).restart();
          else {
            d.node.x = x;
            d.node.y = y;
            this.tree = null;
          }
        } else {
          this.t.x = d.panX + (px - d.startX);
          this.t.y = d.panY + (py - d.startY);
        }
        this.dirty = true;
        return;
      }
      const n = this.nodeAt(px, py);
      const id = n?.id ?? null;
      const overEdge = !n && this.edgeAt(px, py);
      c.dataset['cursor'] = n || overEdge ? 'pointer' : '';
      if (id !== this.hover) {
        this.hover = id;
        this.cb.onHover(id);
        this.dirty = true;
      }
    };
    const up = (ev: Event): void => {
      const e = ev as PointerEvent;
      const d = this.drag;
      if (!d || d.pointer !== e.pointerId) return;
      this.drag = null;
      this.sim.alphaTarget(0);
      c.dataset['cursor'] = '';
      const [px, py] = pos(e);
      if (!d.moved) {
        // A click: select. Dragged nodes stay pinned where they were dropped; clicked ones are released.
        if (d.node) {
          if (!d.node.pinnedByUser) {
            d.node.fx = null;
            d.node.fy = null;
          }
          this.select({ type: 'node', id: d.node.id });
        } else {
          const edge = this.edgeAt(px, py);
          this.select(edge ? { type: 'edge', id: edge.id } : null);
        }
      } else if (d.node) d.node.pinnedByUser = true;
    };
    const wheel = (ev: Event): void => {
      const e = ev as WheelEvent;
      e.preventDefault();
      this.interacted = true;
      const [px, py] = pos(e);
      this.zoomBy(Math.pow(1.0018, -e.deltaY * (e.deltaMode === 1 ? 30 : 1)), px, py);
    };
    const dbl = (ev: Event): void => {
      const [px, py] = pos(ev as MouseEvent);
      const n = this.nodeAt(px, py);
      if (n) this.cb.onExpand(n.id);
    };
    const leave = (): void => {
      if (this.hover) {
        this.hover = null;
        this.cb.onHover(null);
        this.dirty = true;
      }
    };
    this.handlers = [
      ['pointerdown', down],
      ['pointermove', move],
      ['pointerup', up],
      ['pointercancel', up],
      ['wheel', wheel],
      ['dblclick', dbl],
      ['pointerleave', leave],
    ];
    for (const [t, h] of this.handlers) c.addEventListener(t, h, t === 'wheel' ? { passive: false } : undefined);
  }

  private unbind(): void {
    for (const [t, h] of this.handlers) this.canvas.removeEventListener(t, h);
  }

  /** Releases a node pinned by dragging. */
  unpin(id: string): void {
    const n = this.byId.get(id);
    if (!n) return;
    n.fx = null;
    n.fy = null;
    n.pinnedByUser = false;
    this.sim.alpha(0.2).restart();
  }

  // ── Drawing ──

  private shape(ctx: CanvasRenderingContext2D, n: VNode, x: number, y: number, r: number): void {
    const s = KIND_META[n.kind]?.shape ?? 'circle';
    ctx.beginPath();
    if (s === 'square') {
      const q = r * 0.95;
      ctx.roundRect(x - q, y - q, q * 2, q * 2, r * 0.35);
    } else if (s === 'diamond') {
      ctx.moveTo(x, y - r * 1.2);
      ctx.lineTo(x + r * 1.2, y);
      ctx.lineTo(x, y + r * 1.2);
      ctx.lineTo(x - r * 1.2, y);
      ctx.closePath();
    } else if (s === 'hex') {
      for (let i = 0; i < 6; i++) {
        const a = (Math.PI / 3) * i + Math.PI / 6;
        const px = x + Math.cos(a) * r;
        const py = y + Math.sin(a) * r;
        if (i === 0) ctx.moveTo(px, py);
        else ctx.lineTo(px, py);
      }
      ctx.closePath();
    } else ctx.arc(x, y, r, 0, Math.PI * 2);
  }

  private draw(): void {
    const { ctx, palette: p } = this;
    const k = this.t.k;
    ctx.setTransform(this.dpr, 0, 0, this.dpr, 0, 0);
    ctx.clearRect(0, 0, this.w, this.h);
    ctx.save();
    ctx.translate(this.t.x, this.t.y);
    ctx.scale(k, k);

    const sel = this.selection;
    const focusId = sel?.type === 'node' ? sel.id : this.hover;
    const selEdge = sel?.type === 'edge' ? this.edge(sel.id) : null;
    const near = new Set<string>();
    if (focusId) {
      near.add(focusId);
      for (const id of this.adj.get(focusId) ?? []) near.add(id);
    }
    if (selEdge) {
      near.add(selEdge.source.id);
      near.add(selEdge.target.id);
    }
    const hl = this.highlight;
    const dimmed = (id: string): boolean => (near.size > 0 && !near.has(id)) || (hl !== null && near.size === 0 && !hl.has(id));

    // Viewport culling bounds (world coordinates).
    const [vx0, vy0] = this.toWorld(-40, -40);
    const [vx1, vy1] = this.toWorld(this.w + 40, this.h + 40);
    const visible = (n: VNode): boolean => (n.x ?? 0) >= vx0 && (n.x ?? 0) <= vx1 && (n.y ?? 0) >= vy0 && (n.y ?? 0) <= vy1;

    // Edges
    ctx.lineCap = 'round';
    for (const e of this.edges) {
      const s = e.source;
      const t = e.target;
      if (!visible(s) && !visible(t)) continue;
      const isSel = selEdge === e;
      const touches = focusId !== null && (s.id === focusId || t.id === focusId);
      const dim = !isSel && !touches && (dimmed(s.id) || dimmed(t.id));
      ctx.globalAlpha = dim ? 0.07 : 1;
      ctx.beginPath();
      ctx.moveTo(s.x ?? 0, s.y ?? 0);
      ctx.lineTo(t.x ?? 0, t.y ?? 0);
      if (e.kind === 'similar-to') {
        ctx.strokeStyle = e.tier === 'exact' ? p.cls['malicious'] ?? p.edgeStrong : p.cls['suspicious'] ?? p.edgeStrong;
        ctx.globalAlpha *= 0.55 + 0.35 * e.weight;
        ctx.lineWidth = (e.tier === 'exact' ? 1.8 : 1.1) / Math.sqrt(k);
        ctx.setLineDash(e.tier === 'exact' ? [] : [4 / k, 3 / k]);
      } else if (e.kind === 'reported-in' || e.kind === 'matches') {
        ctx.strokeStyle = p.intel;
        ctx.lineWidth = 1.4 / Math.sqrt(k);
        ctx.setLineDash(e.kind === 'matches' ? [2 / k, 3 / k] : []);
      } else if (e.kind === 'member-of') {
        ctx.strokeStyle = p.accent;
        ctx.globalAlpha *= 0.35;
        ctx.lineWidth = 0.9 / Math.sqrt(k);
        ctx.setLineDash([]);
      } else {
        ctx.strokeStyle = touches || isSel ? p.edgeStrong : p.edge;
        ctx.lineWidth = 0.8 / Math.sqrt(k);
        ctx.setLineDash([]);
      }
      if (isSel) {
        ctx.lineWidth = 3 / Math.sqrt(k);
        ctx.strokeStyle = p.accent;
        ctx.setLineDash([]);
        ctx.globalAlpha = 1;
      }
      ctx.stroke();
    }
    ctx.setLineDash([]);

    // Nodes
    for (const n of this.nodes) {
      if (!visible(n)) continue;
      const x = n.x ?? 0;
      const y = n.y ?? 0;
      const dim = dimmed(n.id);
      const isSel = sel?.type === 'node' && sel.id === n.id;
      const color = nodeColor(n, p);
      ctx.globalAlpha = dim ? 0.13 : 1;
      // Restrained glow: only for selected, intelligence-listed and malicious entities.
      const glow = !dim && (isSel || (n.intel && n.intel.strongest > 0) || n.cls === 'malicious');
      if (glow) {
        ctx.shadowColor = isSel ? p.accent : n.intel ? p.intel : color;
        ctx.shadowBlur = (isSel ? 18 : 10) * Math.min(1.5, k);
      }
      this.shape(ctx, n, x, y, n.r);
      ctx.fillStyle = color;
      ctx.fill();
      ctx.shadowBlur = 0;
      ctx.lineWidth = 1.2 / k;
      ctx.strokeStyle = p.bg;
      ctx.stroke();
      if (n.intel && n.intel.strongest > 0) {
        this.shape(ctx, n, x, y, n.r + 3.2 / Math.sqrt(k));
        ctx.strokeStyle = p.intel;
        ctx.lineWidth = 1.6 / k;
        ctx.stroke();
      } else if (n.suspicious) {
        this.shape(ctx, n, x, y, n.r + 2.6 / Math.sqrt(k));
        ctx.strokeStyle = p.cls['suspicious'] ?? color;
        ctx.lineWidth = 1.1 / k;
        ctx.setLineDash([2 / k, 2 / k]);
        ctx.stroke();
        ctx.setLineDash([]);
      }
      if (n.fx !== null && n.fx !== undefined && n.pinnedByUser) {
        ctx.beginPath();
        ctx.arc(x + n.r * 0.75, y - n.r * 0.75, 2.2 / Math.sqrt(k), 0, Math.PI * 2);
        ctx.fillStyle = p.label;
        ctx.fill();
      }
      if (isSel) {
        this.shape(ctx, n, x, y, n.r + 5 / Math.sqrt(k));
        ctx.strokeStyle = p.accent;
        ctx.lineWidth = 2 / k;
        ctx.stroke();
      }
    }

    // Labels (screen-space font size)
    ctx.globalAlpha = 1;
    if (this.labels !== 'none') {
      const fs = 11.5 / k;
      ctx.font = `500 ${fs}px Geist, ui-sans-serif, system-ui, sans-serif`;
      ctx.textBaseline = 'middle';
      for (const n of this.nodes) {
        if (!visible(n)) continue;
        const important = n.kind === 'cluster' || n.kind === 'external';
        const show =
          this.labels === 'all' ||
          near.has(n.id) ||
          (hl?.has(n.id) ?? false) ||
          (important && k > 0.35) ||
          (k > 1.6 && (n.kind !== 'message' || k > 2.2)) ||
          (k > 0.9 && n.degree >= 4 && n.kind !== 'message');
        if (!show) continue;
        if (dimmed(n.id) && !(hl?.has(n.id) ?? false)) continue;
        const text = n.label.length > 48 ? `${n.label.slice(0, 47)}…` : n.label;
        const lx = (n.x ?? 0) + n.r + 5 / k;
        const ly = n.y ?? 0;
        ctx.lineWidth = 3 / k;
        ctx.strokeStyle = p.bg;
        ctx.strokeText(text, lx, ly);
        ctx.fillStyle = important ? (n.kind === 'external' ? p.intel : p.label) : p.label;
        ctx.fillText(text, lx, ly);
      }
    }
    ctx.restore();
  }
}

