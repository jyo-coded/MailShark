// Campaign-correlation benchmark with known ground truth.
//   node scripts/eval/run.mjs correlation [--campaigns 60] [--intel-db <path to intel.db>] [--out lab/out/correlation-eval.json]
//
// Labelled data. No public corpus labels phishing campaigns, so campaigns are generated from REAL
// phishing messages (phishing_pot): each seed message is parsed and re-sent as 2–8 variants that
// rotate what real kits rotate (recipients, Message-IDs, dates, sending IPs, URL tokens, numbers in
// the subject) and, per campaign at random, the sender domain, the landing domain, the attachment
// bytes, the mailer, or use of free-mail senders. Confounders are mixed in: real legitimate mail
// (SpamAssassin) and real, unrelated phishing messages (other phishing_pot samples).
//
// Ground truth is partial and stated as such:
//   positive pair   two variants of the same seed
//   negative pair   a variant and any message not generated from its seed
//   unlabelled      two confounders (they may genuinely be related: same mailing list, same actor)
// Two disjoint seed sets (A, B) are evaluated separately; defaults were not tuned on either.
import { createHash } from 'node:crypto';
import { mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import PostalMime from 'postal-mime';
import { analyzeEmail, ENGINE_VERSION } from '../../engine/src/analyze';
import { buildEml } from '../../engine/test/helpers/mime';
import { correlate, DEFAULT_CORR_CONFIG, type CorrConfig, type CorrEnv, type CorrMessage, type CorrObservation, type CorrelationResult } from '../../platform/server/correlation/engine';
import { IntelStore } from '../../platform/server/intel/store';

const args = process.argv.slice(2);
const arg = (k: string): string | null => (args.includes(k) ? (args[args.indexOf(k) + 1] as string) : null);
const perSplit = Number(arg('--campaigns') ?? 60);
const outPath = arg('--out') ?? 'lab/out/correlation-eval.json';
const intelDb = arg('--intel-db');
const root = process.cwd();

// ── Deterministic randomness ──
function rng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
const R = rng(20261012);
const pick = <T>(xs: T[]): T => xs[Math.floor(R() * xs.length)] as T;
const alnum = 'abcdefghijklmnopqrstuvwxyz0123456789';
const randStr = (n: number, chars = alnum): string => Array.from({ length: n }, () => chars[Math.floor(R() * chars.length)]).join('');
const sameShape = (s: string): string => s.replace(/[a-z]/g, () => randStr(1, 'abcdefghijklmnopqrstuvwxyz')).replace(/[A-Z]/g, () => randStr(1, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ')).replace(/\d/g, () => String(Math.floor(R() * 10)));
const hashOrder = (name: string): string => createHash('sha256').update(name).digest('hex');

// ── Seeds ──
interface Seed {
  name: string;
  subject: string;
  fromName: string;
  fromAddr: string;
  html: string | null;
  text: string | null;
  attachments: { filename: string; contentType: string; content: Uint8Array }[];
  mailer: string | null;
}

async function parseSeed(name: string, raw: Uint8Array): Promise<Seed | null> {
  try {
    const e = await PostalMime.parse(raw, { attachmentEncoding: 'arraybuffer' });
    if (!e.subject || !e.from?.address || (!e.html && !e.text)) return null;
    const atts = (e.attachments ?? [])
      .filter((a) => a.disposition === 'attachment' && a.content && (a.content as ArrayBuffer).byteLength < 2_000_000)
      .slice(0, 2)
      .map((a) => ({ filename: a.filename ?? 'file.bin', contentType: a.mimeType ?? 'application/octet-stream', content: new Uint8Array(a.content as ArrayBuffer) }));
    const mailer = e.headers.find((h) => h.key === 'x-mailer')?.value ?? null;
    return { name, subject: e.subject, fromName: e.from.name || '', fromAddr: e.from.address, html: e.html ?? null, text: e.text ?? null, attachments: atts, mailer };
  } catch {
    return null;
  }
}

// ── Variant generation ──
interface CampaignPlan {
  id: string;
  rotateSender: 'fixed' | 'domain' | 'freemail';
  rotateLinkDomain: boolean;
  polymorphic: boolean;
  sameNet: boolean;
  keepMailer: boolean;
  net: string;
  /** none: identical body · light: numbers and one inserted sentence change · heavy: also ~25% of words replaced. */
  drift: 'none' | 'light' | 'heavy';
}

const FILLER = ['Please act promptly.', 'This is an automated notice.', 'Thank you for your cooperation.', 'Kind regards, the support team.', 'Do not reply to this message.', 'Your prompt attention is appreciated.', 'Reference number below.', 'We value your security.'];
const WORDS = ['account', 'update', 'review', 'secure', 'notice', 'service', 'request', 'information', 'details', 'access', 'verify', 'portal', 'confirm', 'document', 'payment', 'support'];

function driftText(t: string, level: CampaignPlan['drift']): string {
  if (level === 'none') return t;
  let out = t.replace(/\b\d{2,}\b/g, (d) => sameShape(d));
  if (level === 'heavy') out = out.replace(/\b[A-Za-z]{4,}\b/g, (w) => (R() < 0.25 ? pick(WORDS) : w));
  return out;
}

function driftHtml(html: string, level: CampaignPlan['drift']): string {
  if (level === 'none') return html;
  // Only text between tags is changed, so markup, links and structure stay valid.
  const body = html.replace(/>([^<]{3,})</g, (_, txt: string) => `>${driftText(txt, level)}<`);
  const extra = `<p>${pick(FILLER)} ${randStr(6, '0123456789')}</p>`;
  return /<\/body>/i.test(body) ? body.replace(/<\/body>/i, `${extra}</body>`) : body + extra;
}

const TLDS = ['com', 'net', 'top', 'xyz', 'info', 'online', 'site'];
const FREEMAIL = ['gmail.com', 'outlook.com', 'yahoo.com', 'hotmail.com'];

function rewriteUrls(body: string, hostMap: Map<string, string>, plan: CampaignPlan): string {
  return body.replace(/https?:\/\/[^\s"'<>)]+/gi, (url) => {
    let u: URL;
    try {
      u = new URL(url);
    } catch {
      return url;
    }
    if (plan.rotateLinkDomain) {
      const h = u.hostname;
      if (!hostMap.has(h)) hostMap.set(h, `${h.split('.')[0]?.slice(0, 10) || 'portal'}-${randStr(5)}.${pick(TLDS)}`);
      u.hostname = hostMap.get(h) as string;
    }
    // Per-recipient tokens: long alphanumeric runs that contain a digit.
    const tok = (s: string): string => s.replace(/[A-Za-z0-9_-]{6,}/g, (t) => (/\d/.test(t) ? sameShape(t) : t));
    u.pathname = tok(u.pathname);
    u.search = tok(u.search);
    return u.toString();
  });
}

function variant(seed: Seed, plan: CampaignPlan, i: number, baseTime: number): string {
  const domain = seed.fromAddr.split('@')[1] ?? 'sender.example';
  const local = seed.fromAddr.split('@')[0] ?? 'info';
  const fromDomain = plan.rotateSender === 'domain' ? `${domain.split('.')[0]?.slice(0, 12)}-${randStr(4)}.${pick(TLDS)}` : plan.rotateSender === 'freemail' ? pick(FREEMAIL) : domain;
  const fromLocal = plan.rotateSender === 'freemail' ? `${local.replace(/[^a-z]/gi, '').slice(0, 8) || 'support'}${randStr(4, '0123456789')}` : local;
  const victim = `${randStr(6, 'abcdefghijklmnopqrstuvwxyz')}@victim${Math.floor(R() * 5)}.example`;
  const ip = plan.sameNet ? `${plan.net}.${10 + Math.floor(R() * 200)}` : `${45 + Math.floor(R() * 150)}.${Math.floor(R() * 255)}.${Math.floor(R() * 255)}.${1 + Math.floor(R() * 250)}`;
  const when = new Date(baseTime + i * (2 + R() * 30) * 3_600_000);
  const date = when.toUTCString().replace('GMT', '+0000');
  const hostMap = new Map<string, string>();
  const swapRecipient = (s: string): string => s.replace(/[\w.+-]+@(?:pot|phishing\.pot|[\w-]+\.org)\b/gi, victim);
  const html = seed.html ? swapRecipient(rewriteUrls(driftHtml(seed.html, plan.drift), hostMap, plan)) : undefined;
  const text = seed.text ? swapRecipient(rewriteUrls(plan.drift === 'none' ? seed.text : `${driftText(seed.text, plan.drift)}
${pick(FILLER)}`, hostMap, plan)) : undefined;
  const headers: [string, string][] = [
    ['Delivered-To', victim],
    ['Received', `from mail.${fromDomain} (mail.${fromDomain} [${ip}]) by mx.victim.example with ESMTPS id ${randStr(10)} for <${victim}>; ${date}`],
    ['Authentication-Results', `mx.victim.example; spf=${plan.rotateSender === 'freemail' ? 'pass' : pick(['pass', 'none', 'softfail'])} smtp.mailfrom=${fromDomain}; dkim=none; dmarc=none header.from=${fromDomain}`],
    ['From', seed.fromName ? `${seed.fromName} <${fromLocal}@${fromDomain}>` : `${fromLocal}@${fromDomain}`],
    ['To', victim],
    ['Subject', seed.subject.replace(/\d+/g, (d) => sameShape(d))],
    ['Date', date],
    ['Message-ID', `<${randStr(16)}.${randStr(6)}@${fromDomain}>`],
  ];
  if (plan.keepMailer && seed.mailer) headers.push(['X-Mailer', seed.mailer]);
  const attachments = seed.attachments.map((a) => (plan.polymorphic ? { ...a, content: new Uint8Array([...a.content, ...new TextEncoder().encode(`\n<!-- ${randStr(24)} -->`)]) } : a));
  return buildEml({ headers, ...(html !== undefined ? { html } : {}), ...(text !== undefined ? { text } : {}), attachments });
}

// ── Analysis → correlation inputs ──
interface Item {
  msg: CorrMessage;
  obs: CorrObservation[];
  label: string | null; // campaign id, or null for confounders
  kind: 'variant' | 'ham' | 'phish-singleton';
}

async function toItem(id: string, raw: Uint8Array | string, label: string | null, kind: Item['kind']): Promise<Item | null> {
  try {
    const r = await analyzeEmail(typeof raw === 'string' ? new TextEncoder().encode(raw) : raw, { now: new Date('2026-10-12T00:00:00Z') });
    return {
      msg: { id, cls: r.classification?.class ?? null, score: r.score, time: r.fingerprint.time, fp: r.fingerprint },
      obs: (r.iocs ?? []).map((i) => ({ messageId: id, type: i.type, value: i.value, role: i.role, context: i.context ?? null })),
      label,
      kind,
    };
  } catch {
    return null;
  }
}

// ── Metrics ──
interface PairCounts {
  tp: number;
  fp: number;
  fn: number;
}
function prf(c: PairCounts): { precision: number | null; recall: number | null; f1: number | null } {
  const p = c.tp + c.fp ? c.tp / (c.tp + c.fp) : null;
  const r = c.tp + c.fn ? c.tp / (c.tp + c.fn) : null;
  const f = p !== null && r !== null && p + r > 0 ? (2 * p * r) / (p + r) : null;
  const round = (x: number | null): number | null => (x === null ? null : Math.round(x * 1000) / 1000);
  return { precision: round(p), recall: round(r), f1: round(f) };
}

function pairCounts(items: Item[], related: (a: string, b: string) => boolean): PairCounts {
  const c = { tp: 0, fp: 0, fn: 0 };
  for (let i = 0; i < items.length; i++) {
    for (let j = i + 1; j < items.length; j++) {
      const a = items[i] as Item;
      const b = items[j] as Item;
      if (a.label === null && b.label === null) continue; // unlabelled
      const truth = a.label !== null && a.label === b.label;
      const pred = related(a.msg.id, b.msg.id);
      if (pred && truth) c.tp++;
      else if (pred && !truth) c.fp++;
      else if (!pred && truth) c.fn++;
    }
  }
  return c;
}

function ari(truth: string[], pred: string[]): number {
  const n = truth.length;
  const c2 = (x: number): number => (x * (x - 1)) / 2;
  const cont = new Map<string, number>();
  const a = new Map<string, number>();
  const b = new Map<string, number>();
  for (let i = 0; i < n; i++) {
    const t = truth[i] as string;
    const p = pred[i] as string;
    cont.set(`${t}\u0000${p}`, (cont.get(`${t}\u0000${p}`) ?? 0) + 1);
    a.set(t, (a.get(t) ?? 0) + 1);
    b.set(p, (b.get(p) ?? 0) + 1);
  }
  const index = [...cont.values()].reduce((s, x) => s + c2(x), 0);
  const sa = [...a.values()].reduce((s, x) => s + c2(x), 0);
  const sb = [...b.values()].reduce((s, x) => s + c2(x), 0);
  const expected = (sa * sb) / c2(n);
  const max = (sa + sb) / 2;
  return max === expected ? 1 : Math.round(((index - expected) / (max - expected)) * 1000) / 1000;
}

function components(ids: string[], edges: [string, string][]): Map<string, string> {
  const parent = new Map(ids.map((i) => [i, i]));
  const find = (x: string): string => {
    while (parent.get(x) !== x) {
      parent.set(x, parent.get(parent.get(x) as string) as string);
      x = parent.get(x) as string;
    }
    return x;
  };
  for (const [a, b] of edges) parent.set(find(a), find(b));
  return new Map(ids.map((i) => [i, find(i)]));
}

interface Strategy {
  name: string;
  description: string;
  cfg: Partial<CorrConfig>;
  exactOnly?: boolean;
}

const STRATEGIES: Strategy[] = [
  { name: 'exact-artifacts', description: 'Only single decisive shared artifacts (exact tier), connected components', cfg: { useSimilarity: false }, exactOnly: true },
  { name: 'indicators-raw', description: 'Shared indicators, base strengths without specificity discounts or provider neutralisation', cfg: { useSimilarity: false, useSpecificity: false } },
  { name: 'indicators-specific', description: 'Shared indicators with specificity weighting (popularity, fan-out, shared platforms)', cfg: { useSimilarity: false } },
  { name: 'similarity-only', description: 'Layered fingerprint similarity only (no indicator evidence)', cfg: { useIndicators: false } },
  { name: 'combined-components', description: 'Indicators + similarity, connected components', cfg: { clustering: 'components' } },
  { name: 'combined-louvain', description: 'Indicators + similarity, Louvain communities (platform default)', cfg: {} },
];

function evaluate(items: Item[], env: CorrEnv, s: Strategy): Record<string, unknown> {
  const t0 = performance.now();
  const res: CorrelationResult = correlate(
    items.map((i) => i.msg),
    items.flatMap((i) => i.obs),
    env,
    s.cfg,
  );
  const ms = Math.round(performance.now() - t0);
  const edgeSet = new Set(res.edges.filter((e) => !s.exactOnly || e.tier === 'exact').map((e) => (e.a < e.b ? `${e.a}|${e.b}` : `${e.b}|${e.a}`)));
  const related = (a: string, b: string): boolean => edgeSet.has(a < b ? `${a}|${b}` : `${b}|${a}`);
  const ids = items.map((i) => i.msg.id);
  let clusterOf: Map<string, string>;
  if (s.exactOnly) {
    clusterOf = components(ids, [...edgeSet].map((k) => k.split('|') as [string, string]));
  } else {
    clusterOf = new Map(ids.map((i) => [i, `single:${i}`]));
    for (const c of res.clusters) for (const m of c.members) clusterOf.set(m.id, c.id);
  }
  const sameCluster = (a: string, b: string): boolean => clusterOf.get(a) === clusterOf.get(b);
  const variants = items.filter((i) => i.kind === 'variant');
  // Contamination: confounders placed in a cluster together with campaign variants.
  const variantClusters = new Set(variants.map((v) => clusterOf.get(v.msg.id)));
  const contaminated = items.filter((i) => i.kind !== 'variant' && variantClusters.has(clusterOf.get(i.msg.id)) && !(clusterOf.get(i.msg.id) as string).startsWith('single:')).length;
  const pureVariantClusters = (() => {
    const by = new Map<string, Set<string | null>>();
    for (const i of items) {
      const c = clusterOf.get(i.msg.id) as string;
      if (c.startsWith('single:')) continue;
      (by.get(c) ?? by.set(c, new Set()).get(c))?.add(i.label);
    }
    const multi = [...by.values()];
    return { clusters: multi.length, pure: multi.filter((labels) => labels.size === 1).length };
  })();
  // Why false-positive edges exist: what the wrongly linked pairs shared.
  const label = new Map(items.map((i) => [i.msg.id, i.label]));
  const kind = new Map(items.map((i) => [i.msg.id, i.kind]));
  const fpCauses = new Map<string, number>();
  const fpPairs = new Map<string, number>();
  for (const e of res.edges) {
    if (s.exactOnly && e.tier !== 'exact') continue;
    const la = label.get(e.a) ?? null;
    const lb = label.get(e.b) ?? null;
    if ((la === null && lb === null) || (la !== null && la === lb)) continue;
    fpPairs.set(`${kind.get(e.a)}~${kind.get(e.b)}`, (fpPairs.get(`${kind.get(e.a)}~${kind.get(e.b)}`) ?? 0) + 1);
    const top = e.hardLink ? `hard:${e.shared[0]?.family ?? '?'}` : e.indicatorScore >= e.similarity ? `indicators:${e.shared.slice(0, 2).map((x) => x.family).join('+') || 'none'}` : 'similarity';
    fpCauses.set(top, (fpCauses.get(top) ?? 0) + 1);
  }
  return {
    strategy: s.name,
    description: s.description,
    falsePositiveEdgeCauses: Object.fromEntries([...fpCauses.entries()].sort((a, b) => b[1] - a[1])),
    falsePositiveEdgePairs: Object.fromEntries(fpPairs),
    edges: prf(pairCounts(items, related)),
    clusters: prf(pairCounts(items, sameCluster)),
    ariOnVariants: ari(
      variants.map((v) => v.label as string),
      variants.map((v) => clusterOf.get(v.msg.id) as string),
    ),
    confoundersInCampaignClusters: contaminated,
    clusterPurity: pureVariantClusters,
    exactEdges: res.edges.filter((e) => e.tier === 'exact').length,
    totalEdges: res.edges.length,
    ms,
  };
}

// ── Main ──
const pot = join(root, 'datasets', 'phishing_pot', 'email');
const potFiles = readdirSync(pot)
  .filter((f) => f.endsWith('.eml'))
  .sort((a, b) => (hashOrder(a) < hashOrder(b) ? -1 : 1));
const read = (p: string): Uint8Array | null => {
  try {
    return readFileSync(p);
  } catch {
    return null;
  }
};
const store = intelDb ? new IntelStore(intelDb) : null;
const env: CorrEnv = { popularity: (d) => (store ? store.popularity(d) : null), asn: (ip) => (store ? store.asn(ip) : null) };

// phishing_pot holds many copies of the same real campaigns. Seeds and phishing confounders must be
// mutually independent, otherwise "different" campaigns would really be one and the labels wrong:
// no shared sender organisation (free-mail excepted), uncommon link domain, attachment, Reply-To
// organisation or subject template with anything already chosen.
const seen = new Set<string>();
const FREEMAIL_ORGS = new Set(['gmail.com', 'outlook.com', 'hotmail.com', 'yahoo.com', 'aol.com', 'icloud.com', 'live.com', 'mail.ru', 'yandex.ru', 'gmx.com']);
async function independent(raw: Uint8Array): Promise<boolean> {
  let keys: string[];
  try {
    const r = await analyzeEmail(raw, { now: new Date('2026-10-12T00:00:00Z') });
    const fp = r.fingerprint;
    keys = [
      ...(fp.sender.fromOrg && !FREEMAIL_ORGS.has(fp.sender.fromOrg) ? [`from:${fp.sender.fromOrg}`] : []),
      ...(fp.sender.replyToOrg && !FREEMAIL_ORGS.has(fp.sender.replyToOrg) ? [`reply:${fp.sender.replyToOrg}`] : []),
      ...fp.urls.domains.filter((d) => (env.popularity(d) ?? Infinity) > 20_000).map((d) => `link:${d}`),
      ...fp.attachments.sha256.map((h) => `att:${h}`),
      ...(fp.content.subjectTemplate ? [`subj:${fp.content.subjectTemplate}`] : []),
    ];
  } catch {
    return false;
  }
  if (keys.some((k) => seen.has(k))) return false;
  for (const k of keys) seen.add(k);
  return true;
}

const seeds: Seed[] = [];
let cursor = 0;
let skippedRelated = 0;
while (seeds.length < perSplit * 2 && cursor < potFiles.length) {
  const f = potFiles[cursor++] as string;
  const raw = read(join(pot, f));
  if (!raw) continue;
  const s = await parseSeed(f, raw);
  if (!s) continue;
  if (!(await independent(raw))) {
    skippedRelated++;
    continue;
  }
  seeds.push(s);
}
const singletonFiles: string[] = [];
while (singletonFiles.length < perSplit * 3 && cursor < potFiles.length) {
  const f = potFiles[cursor++] as string;
  const raw = read(join(pot, f));
  if (!raw) continue;
  if (await independent(raw)) singletonFiles.push(f);
  else skippedRelated++;
}
const hamDir = join(root, 'datasets', 'spamassassin', 'easy_ham');
const hamFiles = readdirSync(hamDir)
  .filter((f) => f !== 'cmds' && !statSync(join(hamDir, f)).isDirectory())
  .sort((a, b) => (hashOrder(a) < hashOrder(b) ? -1 : 1))
  .slice(0, perSplit * 4);

const out: Record<string, unknown> = {
  generatedAt: new Date().toISOString(),
  engine: ENGINE_VERSION,
  design: 'Variants of real phishing_pot messages (2–8 per campaign) + real SpamAssassin ham + unrelated phishing_pot singletons; pairwise metrics over labelled pairs; ARI over variants only.',
  intelEnv: store ? `popularity/ASN from ${intelDb}` : 'none (no popularity or ASN data)',
  defaults: DEFAULT_CORR_CONFIG,
  independence: 'Seeds and phishing confounders share no sender organisation (free-mail excepted), uncommon link domain (Tranco rank > 20,000 or unranked), attachment, Reply-To organisation or subject template.',
  candidatesSkippedAsRelated: skippedRelated,
  splits: {},
};
for (const [splitName, offset] of [['A', 0], ['B', 1]] as const) {
  const t0 = Date.now();
  const items: Item[] = [];
  const mine = seeds.filter((_, i) => i % 2 === offset);
  const plans: Record<string, number> = { fixed: 0, domain: 0, freemail: 0, rotateLinkDomain: 0, polymorphic: 0, sameNet: 0 };
  let variantCount = 0;
  for (const [ci, seed] of mine.entries()) {
    const plan: CampaignPlan = {
      id: `${splitName}${ci}`,
      rotateSender: R() < 0.35 ? 'fixed' : R() < 0.7 ? 'domain' : 'freemail',
      rotateLinkDomain: R() < 0.5,
      polymorphic: R() < 0.5,
      sameNet: R() < 0.5,
      keepMailer: R() < 0.6,
      net: `${100 + Math.floor(R() * 100)}.${Math.floor(R() * 255)}.${Math.floor(R() * 255)}`,
      drift: R() < 0.3 ? 'none' : R() < 0.6 ? 'light' : 'heavy',
    };
    plans[`drift-${plan.drift}`] = (plans[`drift-${plan.drift}`] ?? 0) + 1;
    plans[plan.rotateSender] = (plans[plan.rotateSender] ?? 0) + 1;
    if (plan.rotateLinkDomain) plans['rotateLinkDomain'] = (plans['rotateLinkDomain'] ?? 0) + 1;
    if (plan.polymorphic && seed.attachments.length) plans['polymorphic'] = (plans['polymorphic'] ?? 0) + 1;
    if (plan.sameNet) plans['sameNet'] = (plans['sameNet'] ?? 0) + 1;
    const k = 2 + Math.floor(R() * 7);
    const base = Date.UTC(2026, 8, 1) + Math.floor(R() * 30) * 86_400_000;
    for (let i = 0; i < k; i++) {
      const it = await toItem(`${plan.id}.${i}`, variant(seed, plan, i, base), plan.id, 'variant');
      if (it) {
        items.push(it);
        variantCount++;
      }
    }
  }
  for (const [i, f] of singletonFiles.filter((_, j) => j % 2 === offset).entries()) {
    const raw = read(join(pot, f));
    const it = raw ? await toItem(`${splitName}p${i}`, raw, null, 'phish-singleton') : null;
    if (it) items.push(it);
  }
  for (const [i, f] of hamFiles.filter((_, j) => j % 2 === offset).entries()) {
    let raw = readFileSync(join(hamDir, f));
    if (raw.subarray(0, 5).toString('latin1') === 'From ') raw = raw.subarray(raw.indexOf(10) + 1);
    const it = await toItem(`${splitName}h${i}`, raw, null, 'ham');
    if (it) items.push(it);
  }
  const strategies = STRATEGIES.map((s) => evaluate(items, env, s));
  const sweep = [0.5, 0.55, 0.6, 0.65, 0.7, 0.75, 0.8].map((th) => ({ edgeThreshold: th, ...evaluate(items, env, { name: `combined-louvain@${th}`, description: '', cfg: { edgeThreshold: th } }) }));
  (out['splits'] as Record<string, unknown>)[splitName] = {
    campaigns: mine.length,
    variants: variantCount,
    phishSingletons: items.filter((i) => i.kind === 'phish-singleton').length,
    ham: items.filter((i) => i.kind === 'ham').length,
    campaignPlans: plans,
    strategies,
    thresholdSweep: sweep.map((x) => ({ edgeThreshold: x.edgeThreshold, edges: x.edges, clusters: x.clusters, ariOnVariants: x.ariOnVariants, confoundersInCampaignClusters: x.confoundersInCampaignClusters })),
    seconds: Math.round((Date.now() - t0) / 1000),
  };
  process.stderr.write(`split ${splitName}: ${items.length} messages, ${Math.round((Date.now() - t0) / 1000)}s\n`);
}
mkdirSync(dirname(outPath), { recursive: true });
writeFileSync(outPath, JSON.stringify(out, null, 2));
for (const [name, sp] of Object.entries(out['splits'] as Record<string, { strategies: Record<string, unknown>[]; campaigns: number; variants: number; phishSingletons: number; ham: number }>)) {
  console.log(`\nSplit ${name}: ${sp.campaigns} campaigns / ${sp.variants} variants + ${sp.phishSingletons} unrelated phishing + ${sp.ham} ham`);
  console.log('strategy                 edge P   edge R   edge F1 | clus P   clus R   clus F1 |  ARI   contam');
  for (const s of sp.strategies as { strategy: string; edges: ReturnType<typeof prf>; clusters: ReturnType<typeof prf>; ariOnVariants: number; confoundersInCampaignClusters: number }[]) {
    const f = (x: number | null): string => (x === null ? '  —   ' : x.toFixed(3)).padStart(7);
    console.log(`${s.strategy.padEnd(24)} ${f(s.edges.precision)}  ${f(s.edges.recall)}  ${f(s.edges.f1)} | ${f(s.clusters.precision)}  ${f(s.clusters.recall)}  ${f(s.clusters.f1)} | ${f(s.ariOnVariants)} ${String(s.confoundersInCampaignClusters).padStart(5)}`);
  }
}
for (const [name, sp] of Object.entries(out['splits'] as Record<string, { thresholdSweep: { edgeThreshold: number; clusters: ReturnType<typeof prf>; ariOnVariants: number; confoundersInCampaignClusters: number }[]; strategies: { strategy: string; falsePositiveEdgeCauses: Record<string, number>; falsePositiveEdgePairs: Record<string, number> }[] }>)) {
  console.log(`\nSplit ${name} threshold sweep (combined-louvain): ` + sp.thresholdSweep.map((x) => `${x.edgeThreshold}: F1 ${x.clusters.f1} ARI ${x.ariOnVariants} contam ${x.confoundersInCampaignClusters}`).join(' | '));
  const d = sp.strategies.find((x) => x.strategy === 'combined-louvain');
  console.log(`Split ${name} false-positive edges (default): causes ${JSON.stringify(d?.falsePositiveEdgeCauses)} pairs ${JSON.stringify(d?.falsePositiveEdgePairs)}`);
}
console.log(`\n→ ${outPath}`);
