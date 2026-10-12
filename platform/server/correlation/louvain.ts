// Louvain community detection (Blondel et al., "Fast unfolding of communities in large networks",
// J. Stat. Mech. 2008) on a weighted undirected graph. Deterministic: nodes are visited in sorted
// order, so the same evidence always produces the same clusters (reproducibility).
//
// Why Louvain rather than connected components: a component held together by a single weak edge
// (two operations that happen to share one tracking domain) has low modularity and is split, while
// a dense group of mutually similar messages stays together.

export interface WEdge {
  a: string;
  b: string;
  w: number;
}

type Adj = Map<number, Map<number, number>>;

function addEdge(adj: Adj, u: number, v: number, w: number): void {
  if (!adj.has(u)) adj.set(u, new Map());
  if (!adj.has(v)) adj.set(v, new Map());
  const au = adj.get(u) as Map<number, number>;
  au.set(v, (au.get(v) ?? 0) + w);
  if (u !== v) {
    const av = adj.get(v) as Map<number, number>;
    av.set(u, (av.get(u) ?? 0) + w);
  }
}

function degree(adj: Adj, u: number): number {
  let d = 0;
  for (const [v, w] of adj.get(u) ?? []) d += v === u ? 2 * w : w;
  return d;
}

function totalWeight(adj: Adj): number {
  let m = 0;
  for (const [u, nbrs] of adj) for (const [v, w] of nbrs) if (v >= u) m += w;
  return m;
}

/** One pass of local moves. Returns the community of each node and whether anything moved. */
function oneLevel(adj: Adj, n: number, resolution: number): { com: number[]; improved: boolean } {
  const m = totalWeight(adj);
  const com = Array.from({ length: n }, (_, i) => i);
  if (m === 0) return { com, improved: false };
  const deg = Array.from({ length: n }, (_, i) => degree(adj, i));
  const stot = [...deg];
  let improved = false;
  for (let pass = 0; pass < 100; pass++) {
    let moves = 0;
    for (let u = 0; u < n; u++) {
      const weights2com = new Map<number, number>();
      for (const [v, w] of adj.get(u) ?? []) {
        if (v === u) continue;
        weights2com.set(com[v] as number, (weights2com.get(com[v] as number) ?? 0) + w);
      }
      const cur = com[u] as number;
      const du = deg[u] as number;
      stot[cur] = (stot[cur] as number) - du;
      const removeCost = -(weights2com.get(cur) ?? 0) / m + (resolution * (stot[cur] as number) * du) / (2 * m * m);
      let best = cur;
      let bestGain = 0;
      for (const c of [...weights2com.keys()].sort((x, y) => x - y)) {
        const gain = removeCost + (weights2com.get(c) as number) / m - (resolution * (stot[c] as number) * du) / (2 * m * m);
        if (gain > bestGain + 1e-12) {
          bestGain = gain;
          best = c;
        }
      }
      stot[best] = (stot[best] as number) + du;
      if (best !== cur) {
        com[u] = best;
        moves++;
        improved = true;
      }
    }
    if (!moves) break;
  }
  // Renumber communities 0..k-1 in order of first appearance.
  const remap = new Map<number, number>();
  return { com: com.map((c) => (remap.has(c) ? (remap.get(c) as number) : (remap.set(c, remap.size), remap.size - 1))), improved };
}

/** Community id per node. Nodes without edges get their own community. */
export function louvain(nodes: string[], edges: WEdge[], resolution = 1): Map<string, number> {
  const ids = [...new Set(nodes)].sort();
  const index = new Map(ids.map((id, i) => [id, i]));
  let adj: Adj = new Map();
  for (let i = 0; i < ids.length; i++) adj.set(i, new Map());
  for (const e of [...edges].sort((x, y) => (x.a + '|' + x.b < y.a + '|' + y.b ? -1 : 1))) {
    const u = index.get(e.a);
    const v = index.get(e.b);
    if (u === undefined || v === undefined || e.w <= 0) continue;
    addEdge(adj, u, v, e.w);
  }
  // membership[i] = community of original node i at the current level
  let membership = ids.map((_, i) => i);
  let n = ids.length;
  for (let level = 0; level < 32; level++) {
    const { com, improved } = oneLevel(adj, n, resolution);
    if (!improved) break;
    membership = membership.map((c) => com[c] as number);
    const k = Math.max(...com) + 1;
    const next: Adj = new Map();
    for (let i = 0; i < k; i++) next.set(i, new Map());
    for (const [u, nbrs] of adj) for (const [v, w] of nbrs) if (v >= u) addEdge(next, com[u] as number, com[v] as number, w);
    adj = next;
    n = k;
  }
  return new Map(ids.map((id, i) => [id, membership[i] as number]));
}

/** Newman modularity of a partition (for tests and diagnostics). */
export function modularity(edges: WEdge[], part: Map<string, number>): number {
  let m = 0;
  const deg = new Map<string, number>();
  for (const e of edges) {
    m += e.w;
    deg.set(e.a, (deg.get(e.a) ?? 0) + e.w);
    deg.set(e.b, (deg.get(e.b) ?? 0) + e.w);
  }
  if (!m) return 0;
  let q = 0;
  for (const e of edges) if (part.get(e.a) === part.get(e.b)) q += e.w / m;
  const tot = new Map<number, number>();
  for (const [node, d] of deg) {
    const c = part.get(node) as number;
    tot.set(c, (tot.get(c) ?? 0) + d);
  }
  for (const t of tot.values()) q -= (t / (2 * m)) ** 2;
  return q;
}
