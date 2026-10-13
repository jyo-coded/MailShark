// Campaign correlation inside an investigation.
//
// Two messages are related when they share *specific* artifacts, or when the engine's layered
// similarity (content, links, attachments, infrastructure, sender, intent, timing) says they come
// from the same operation. Relationships are tiered:
//   exact     a shared artifact strong enough on its own (attachment hash, unique URL, reply-to
//             mailbox, wallet, phone number, ESP campaign id …)
//   probable  combined evidence above the edge threshold, without a single decisive artifact
// Clusters are Louvain communities of the evidence-weighted graph. Every edge keeps the list of
// artifacts and similarity layers that justify it, so each association can be reviewed.
import { createHash } from 'node:crypto';
import type { Fingerprint } from '../../../engine/src/types';
import { similarity, type Layer } from '../../../engine/src/campaign/similarity';
import { profileCampaign, type CampaignProfile } from '../../../engine/src/campaign/cluster';
import { brandById } from '../../../engine/src/data/brands';
import { ESP_TRACKING_DOMAINS, FREE_HOSTING_SUFFIXES, URL_SHORTENERS, hostMatchesSuffix, isFreemail } from '../../../engine/src/util/domain';
import { louvain, type WEdge } from './louvain';
import { registrable } from '../intel/normalize';

export interface CorrMessage {
  id: string;
  cls: string | null;
  score: number | null;
  time: number | null;
  fp: Fingerprint;
}

export interface CorrObservation {
  messageId: string;
  type: string;
  value: string;
  role: string;
  context: string | null;
}

export interface CorrEnv {
  popularity: (domain: string | null) => number | null;
  asn: (ip: string) => { asn: number; name: string | null } | null;
}

export interface CorrConfig {
  /** Combined evidence needed for a probable relationship (0–1). */
  edgeThreshold: number;
  /** Strength at which one shared artifact alone makes an exact relationship (0–1). */
  exactThreshold: number;
  /** Louvain resolution; >1 favours smaller clusters. */
  resolution: number;
  maxCandidatesPerMessage: number;
  /** Index keys shared by more messages than this are too common to propose candidates. */
  maxKeyFanout: number;
  /** Ablation switches used by the evaluation harness. */
  useIndicators?: boolean;
  useSimilarity?: boolean;
  useSpecificity?: boolean;
  clustering?: 'louvain' | 'components';
}

export const DEFAULT_CORR_CONFIG: CorrConfig = {
  edgeThreshold: 0.6,
  exactThreshold: 0.75,
  resolution: 1,
  maxCandidatesPerMessage: 300,
  maxKeyFanout: 200,
};

export type Family =
  | 'attachment'
  | 'url'
  | 'url-generic'
  | 'link-host'
  | 'link-domain'
  | 'reply-to'
  | 'from-address'
  | 'from-domain'
  | 'return-path'
  | 'origin-ip'
  | 'client-ip'
  | 'auth-sender'
  | 'phone'
  | 'wallet'
  | 'esp-campaign'
  | 'dkim-domain';

export const FAMILY_BASE: Record<Family, { base: number; label: string }> = {
  attachment: { base: 0.95, label: 'Identical attachment (SHA-256)' },
  url: { base: 0.85, label: 'Same link (URL with unique path/token)' },
  'url-generic': { base: 0.55, label: 'Same link' },
  'link-host': { base: 0.6, label: 'Same link host' },
  'link-domain': { base: 0.45, label: 'Same link domain' },
  'reply-to': { base: 0.85, label: 'Same Reply-To mailbox' },
  'from-address': { base: 0.55, label: 'Same sender address' },
  'from-domain': { base: 0.35, label: 'Same sender domain' },
  'return-path': { base: 0.4, label: 'Same envelope sender' },
  'origin-ip': { base: 0.5, label: 'Same sending IP' },
  'client-ip': { base: 0.8, label: 'Same submitting client IP' },
  'auth-sender': { base: 0.85, label: 'Same authenticated sending account' },
  phone: { base: 0.9, label: 'Same phone number' },
  wallet: { base: 0.95, label: 'Same cryptocurrency wallet' },
  'esp-campaign': { base: 0.9, label: 'Same bulk-mail campaign ID' },
  'dkim-domain': { base: 0.3, label: 'Same DKIM signing domain' },
};

const SHARED_SENDING_AS = /google|microsoft|outlook|amazon|sendgrid|twilio|mailchimp|rocket science|mailgun|sparkpost|messagebird|salesforce|exacttarget|zoho|yahoo|oath|apple|proofpoint|mimecast|messagelabs|broadcom|cisco|ironport|barracuda|postmark|wildbit|brevo|sendinblue|mailjet|sinch|constant contact|hubspot|klaviyo|braze|iterable|amazon ses|smtp2go|socketlabs|elastic email|mailerlite|netcore|pepipost/i;

export interface SharedIndicator {
  family: Family;
  type: string;
  value: string;
  strength: number;
  discounts: string[];
}

export interface PairEvidence {
  a: string;
  b: string;
  tier: 'exact' | 'probable';
  score: number;
  indicatorScore: number;
  similarity: number;
  layers: Partial<Record<Layer, number | null>>;
  hardLink: string | null;
  shared: SharedIndicator[];
}

export interface ClusterResult {
  id: string;
  members: { id: string; strength: number }[];
  cohesion: number;
  density: number;
  exactEdges: number;
  confidence: 'high' | 'medium' | 'low';
  label: string;
  verdict: 'threat' | 'bulk' | 'mixed';
  firstSeen: number | null;
  lastSeen: number | null;
  profile: CampaignProfile;
  sharedIndicators: (SharedIndicator & { messages: number })[];
}

export interface CorrelationResult {
  edges: PairEvidence[];
  clusters: ClusterResult[];
  stats: { messages: number; candidatePairs: number; edges: number; exactEdges: number; clusters: number; clusteredMessages: number; ms: number };
}

// ── Indicator families & specificity ─────────────────────────────────────────

const TOKENISH = /\/[^/]*\d[^/]*[a-z][^/]*|\/[^/]*[a-z][^/]*\d[^/]*|\?./i;

export function familyOf(o: CorrObservation): Family | null {
  const r = o.role;
  switch (o.type) {
    case 'sha256':
      return r === 'attachment' ? 'attachment' : null;
    case 'url':
      if (r !== 'link' && r !== 'qr-link' && r !== 'attachment-link') return null;
      try {
        const u = new URL(o.value);
        return TOKENISH.test(u.pathname + u.search) && (u.pathname + u.search).length > 6 ? 'url' : 'url-generic';
      } catch {
        return 'url-generic';
      }
    case 'hostname':
      return r === 'link-host' ? 'link-host' : null;
    case 'domain':
      return r === 'link-domain' ? 'link-domain' : r === 'from' ? 'from-domain' : r === 'dkim-domain' ? 'dkim-domain' : null;
    case 'email':
      return r === 'reply-to' ? 'reply-to' : r === 'from' ? 'from-address' : r === 'return-path' ? 'return-path' : r === 'authenticated-sender' ? 'auth-sender' : null;
    case 'ipv4':
    case 'ipv6':
      return r === 'origin-ip' ? 'origin-ip' : r === 'client-ip' ? 'client-ip' : r === 'link-host' ? 'link-host' : null;
    case 'phone':
      return 'phone';
    case 'btc':
    case 'eth':
    case 'xmr':
      return 'wallet';
    case 'esp-campaign':
      return 'esp-campaign';
    default:
      return null;
  }
}

function hostOf(o: CorrObservation): string | null {
  if (o.type === 'url') {
    try {
      return new URL(o.value).hostname.toLowerCase();
    } catch {
      return null;
    }
  }
  if (o.type === 'email') return o.value.slice(o.value.lastIndexOf('@') + 1).toLowerCase();
  if (o.type === 'hostname' || o.type === 'domain') return o.value.toLowerCase();
  return null;
}

/** Base strength of an observation's family, discounted for shared or popular infrastructure. */
export function specificity(o: CorrObservation, family: Family, env: CorrEnv, df: number, senderDiversity: number, use = true): { strength: number; discounts: string[] } {
  let s = FAMILY_BASE[family].base;
  const discounts: string[] = [];
  if (!use) return { strength: s, discounts };
  const cut = (f: number, why: string): void => {
    s *= f;
    discounts.push(why);
  };
  const host = hostOf(o);
  const reg = host ? registrable(host) : null;
  if (family === 'attachment' && o.context && /inline/.test(o.context) && /^(png|jpeg|gif|bmp|webp)/.test(o.context)) cut(0.3, 'inline image (logos and signatures repeat across unrelated mail)');
  if (host && reg && ['url', 'url-generic', 'link-host', 'link-domain'].includes(family)) {
    if (ESP_TRACKING_DOMAINS.has(reg) || hostMatchesSuffix(host, URL_SHORTENERS)) cut(family.startsWith('url') ? 0.6 : 0.1, `shared tracking/shortener infrastructure (${reg})`);
    const platform = hostMatchesSuffix(host, FREE_HOSTING_SUFFIXES);
    if (platform) {
      if (host === platform || (family === 'link-domain' && reg === platform)) cut(0.1, `shared hosting platform (${platform})`);
      else if (family === 'link-domain') cut(0.2, `registrable domain of a hosting platform (${reg})`);
    }
    const rank = env.popularity(reg);
    if (rank !== null && rank <= 100_000) cut(family.startsWith('url') ? 0.5 : 0.1, `popular site (Tranco #${rank})`);
    else if (rank !== null && rank <= 1_000_000) cut(0.7, `widely used site (Tranco #${rank})`);
  }
  if (host && (family === 'from-domain' || family === 'return-path') && isFreemail(host)) cut(0.02, `free-mail provider (${host})`);
  if (family === 'from-domain' && reg) {
    const rank = env.popularity(reg);
    if (rank !== null && rank <= 100_000) cut(0.3, `popular sender domain (Tranco #${rank})`);
  }
  if (family === 'origin-ip') {
    const a = env.asn(o.value);
    if (a && a.name && SHARED_SENDING_AS.test(a.name)) cut(0.2, `shared sending platform (AS${a.asn} ${a.name})`);
  }
  if (df >= 4 && senderDiversity >= 0.6) cut(0.4, `seen with ${Math.round(senderDiversity * df)} different sender domains in this case`);
  return { strength: Math.round(s * 1000) / 1000, discounts };
}

// ── Provider-aware neutralisation ────────────────────────────────────────────

// Large mailbox providers: messages they send share header order, Message-ID format, sending
// networks and DKIM domains no matter who wrote them.
const PROVIDER_ORGS = new Set(['gmail.com', 'google.com', 'googlemail.com', 'outlook.com', 'hotmail.com', 'live.com', 'microsoft.com', 'office365.com', 'onmicrosoft.com', 'yahoo.com', 'yahoodns.net', 'aol.com', 'icloud.com', 'me.com', 'apple.com', 'zoho.com', 'zohomail.com', 'protonmail.ch', 'proton.me', 'gmx.net', 'gmx.com', 'web.de', 'mail.ru', 'yandex.ru', 'yandex.net', 'qq.com', '163.com']);

function sharedLinkDomain(d: string, env: CorrEnv): boolean {
  if (ESP_TRACKING_DOMAINS.has(d) || URL_SHORTENERS.has(d) || FREE_HOSTING_SUFFIXES.includes(d)) return true;
  const rank = env.popularity(d);
  return rank !== null && rank <= 100_000;
}

/**
 * A copy of the fingerprint without the attributes that a shared platform, not the sender,
 * determines. Two unrelated Gmail users share Gmail's header order and sending networks; two
 * newsletters both linking to Google Forms share google.com. Such equality is not evidence of a
 * common operation, so it is removed before similarity is computed. Messages sent from an actor's
 * own infrastructure (typical of phishing kits) keep all of it.
 */
export function neutralizeFingerprint(fp: Fingerprint, env: CorrEnv): Fingerprint {
  const c: Fingerprint = JSON.parse(JSON.stringify(fp)) as Fingerprint;
  const fromDomain = fp.sender.fromDomain ?? '';
  const freemail = !!fromDomain && isFreemail(fromDomain);
  const asn = fp.infra.originIp ? env.asn(fp.infra.originIp) : null;
  const viaProvider =
    freemail ||
    !!fp.infra.esp ||
    fp.infra.dkimDomains.some((d) => PROVIDER_ORGS.has(d)) ||
    (fp.infra.originOrg !== null && PROVIDER_ORGS.has(fp.infra.originOrg)) ||
    (asn !== null && asn.name !== null && SHARED_SENDING_AS.test(asn.name));
  if (viaProvider) {
    c.infra.originIp = null;
    c.infra.originNet = null;
    c.infra.originOrg = null;
    c.infra.headerOrder = null;
    c.infra.messageIdTemplate = null;
    c.infra.messageIdDomain = null;
    c.infra.dkimDomains = [];
    c.infra.dkimSelectors = [];
    c.infra.dkimHeaderSet = null;
  }
  if (freemail) {
    c.sender.fromOrg = null;
    c.sender.fromDomain = null;
    c.sender.returnPathOrg = c.sender.returnPathOrg && isFreemail(c.sender.returnPathOrg) ? null : c.sender.returnPathOrg;
  }
  c.urls.domains = fp.urls.domains.filter((d) => !sharedLinkDomain(d, env));
  c.urls.templates = fp.urls.templates.filter((t) => !sharedLinkDomain(t.slice(0, t.indexOf('/') < 0 ? t.length : t.indexOf('/')), env));
  c.urls.paths = [...new Set(c.urls.templates.map((t) => t.slice(t.indexOf('/'))).filter((p) => p.split('/').filter(Boolean).length >= 2))].sort();
  return c;
}

// ── Correlation ──────────────────────────────────────────────────────────────

const pairKey = (a: string, b: string): string => (a < b ? `${a}\u0000${b}` : `${b}\u0000${a}`);

export function correlate(messages: CorrMessage[], observations: CorrObservation[], env: CorrEnv, cfgIn: Partial<CorrConfig> = {}): CorrelationResult {
  const t0 = performance.now();
  const cfg: CorrConfig = { ...DEFAULT_CORR_CONFIG, ...cfgIn };
  const useIndicators = cfg.useIndicators !== false;
  const useSimilarity = cfg.useSimilarity !== false;
  const byId = new Map(messages.map((m) => [m.id, m]));

  // Indicator index: key → messages; plus per-message indicator strengths.
  const keyMessages = new Map<string, Set<string>>();
  const keyObs = new Map<string, { o: CorrObservation; family: Family }>();
  for (const o of observations) {
    if (!byId.has(o.messageId)) continue;
    const family = familyOf(o);
    if (!family) continue;
    const key = `${family}|${o.type}|${o.value}`;
    if (!keyMessages.has(key)) keyMessages.set(key, new Set());
    (keyMessages.get(key) as Set<string>).add(o.messageId);
    if (!keyObs.has(key)) keyObs.set(key, { o, family });
  }
  const strengths = new Map<string, { strength: number; discounts: string[] }>();
  for (const [key, ids] of keyMessages) {
    const { o, family } = keyObs.get(key) as { o: CorrObservation; family: Family };
    const senders = new Set([...ids].map((id) => byId.get(id)?.fp.sender.fromOrg ?? id));
    strengths.set(key, specificity(o, family, env, ids.size, ids.size ? senders.size / ids.size : 0, cfg.useSpecificity !== false));
  }

  // Candidate pairs: shared indicator keys + engine fingerprint keys (LSH bands, templates, hashes).
  const fpKeyMessages = new Map<string, string[]>();
  if (useSimilarity) {
    for (const m of messages) for (const k of m.fp.keys ?? []) (fpKeyMessages.get(k) ?? fpKeyMessages.set(k, []).get(k))?.push(m.id);
  }
  const candidates = new Map<string, Map<string, number>>();
  const bump = (a: string, b: string): void => {
    if (a === b) return;
    const [x, y] = a < b ? [a, b] : [b, a];
    let m = candidates.get(x);
    if (!m) candidates.set(x, (m = new Map()));
    m.set(y, (m.get(y) ?? 0) + 1);
  };
  if (useIndicators) {
    for (const [key, ids] of keyMessages) {
      if (ids.size < 2 || ids.size > cfg.maxKeyFanout) continue;
      if ((strengths.get(key)?.strength ?? 0) < 0.05) continue;
      const list = [...ids];
      for (let i = 0; i < list.length; i++) for (let j = i + 1; j < list.length; j++) bump(list[i] as string, list[j] as string);
    }
  }
  for (const ids of fpKeyMessages.values()) {
    if (ids.length < 2 || ids.length > cfg.maxKeyFanout) continue;
    for (let i = 0; i < ids.length; i++) for (let j = i + 1; j < ids.length; j++) bump(ids[i] as string, ids[j] as string);
  }

  const neutralCache = new Map<string, Fingerprint>();
  const neutral = (m: CorrMessage): Fingerprint => {
    let fp = neutralCache.get(m.id);
    if (!fp) {
      fp = cfg.useSpecificity === false ? m.fp : neutralizeFingerprint(m.fp, env);
      neutralCache.set(m.id, fp);
    }
    return fp;
  };

  // Per-message shared-indicator lookup.
  const msgKeys = new Map<string, Set<string>>();
  for (const [key, ids] of keyMessages) for (const id of ids) (msgKeys.get(id) ?? msgKeys.set(id, new Set()).get(id))?.add(key);

  const edges: PairEvidence[] = [];
  let candidatePairs = 0;
  for (const [a, partners] of candidates) {
    const ranked = [...partners.entries()].sort((x, y) => y[1] - x[1]).slice(0, cfg.maxCandidatesPerMessage);
    for (const [b] of ranked) {
      candidatePairs++;
      const ma = byId.get(a) as CorrMessage;
      const mb = byId.get(b) as CorrMessage;
      const shared: SharedIndicator[] = [];
      if (useIndicators) {
        const ka = msgKeys.get(a) ?? new Set<string>();
        const kb = msgKeys.get(b) ?? new Set<string>();
        for (const k of ka) {
          if (!kb.has(k)) continue;
          const { o, family } = keyObs.get(k) as { o: CorrObservation; family: Family };
          const st = strengths.get(k) as { strength: number; discounts: string[] };
          shared.push({ family, type: o.type, value: o.value, strength: st.strength, discounts: st.discounts });
        }
      }
      // Noisy-OR over families: several URLs from one email are one piece of evidence, not five.
      const bestPerFamily = new Map<Family, number>();
      for (const s of shared) bestPerFamily.set(s.family, Math.max(bestPerFamily.get(s.family) ?? 0, s.strength));
      let miss = 1;
      for (const v of bestPerFamily.values()) miss *= 1 - v;
      const indicatorScore = 1 - miss;
      const sim = useSimilarity ? similarity(neutral(ma), neutral(mb)) : { score: 0, layers: {}, hardLink: null };
      const score = 1 - (1 - indicatorScore) * (1 - sim.score);
      const decisive = shared.some((s) => s.strength >= cfg.exactThreshold);
      if (!decisive && score < cfg.edgeThreshold) continue;
      shared.sort((x, y) => y.strength - x.strength);
      edges.push({
        a: a < b ? a : b,
        b: a < b ? b : a,
        tier: decisive ? 'exact' : 'probable',
        score: Math.round(score * 1000) / 1000,
        indicatorScore: Math.round(indicatorScore * 1000) / 1000,
        similarity: sim.score,
        layers: sim.layers,
        hardLink: sim.hardLink,
        shared: shared.slice(0, 20),
      });
    }
  }

  // Clusters.
  const nodes = [...new Set(edges.flatMap((e) => [e.a, e.b]))];
  let part: Map<string, number>;
  if (cfg.clustering === 'components') {
    part = components(nodes, edges);
  } else {
    part = louvain(nodes, edges.map((e): WEdge => ({ a: e.a, b: e.b, w: e.score })), cfg.resolution);
  }
  const groups = new Map<number, string[]>();
  for (const [id, c] of part) (groups.get(c) ?? groups.set(c, []).get(c))?.push(id);
  const edgeMap = new Map(edges.map((e) => [pairKey(e.a, e.b), e]));
  const clusters: ClusterResult[] = [];
  for (const ids of groups.values()) {
    if (ids.length < 2) continue;
    ids.sort();
    const internal: PairEvidence[] = [];
    for (let i = 0; i < ids.length; i++) for (let j = i + 1; j < ids.length; j++) {
      const e = edgeMap.get(pairKey(ids[i] as string, ids[j] as string));
      if (e) internal.push(e);
    }
    if (!internal.length) continue;
    const cohesion = internal.reduce((s, e) => s + e.score, 0) / internal.length;
    const density = internal.length / ((ids.length * (ids.length - 1)) / 2);
    const exactEdges = internal.filter((e) => e.tier === 'exact').length;
    const memberStrength = new Map<string, number[]>();
    for (const e of internal) {
      (memberStrength.get(e.a) ?? memberStrength.set(e.a, []).get(e.a))?.push(e.score);
      (memberStrength.get(e.b) ?? memberStrength.set(e.b, []).get(e.b))?.push(e.score);
    }
    const members = ids.map((id) => {
      const s = memberStrength.get(id) ?? [0];
      return { id, strength: Math.round(Math.max(...s) * 1000) / 1000 };
    });
    const fps = ids.map((id) => (byId.get(id) as CorrMessage).fp);
    const profile = profileCampaign(fps);
    const classes = ids.map((id) => byId.get(id)?.cls ?? null);
    const threats = classes.filter((c) => c === 'malicious' || c === 'suspicious').length;
    const verdict: ClusterResult['verdict'] = threats === 0 ? 'bulk' : threats === ids.length ? 'threat' : 'mixed';
    const confidence: ClusterResult['confidence'] = cohesion >= 0.75 && density >= 0.5 && exactEdges >= 1 ? 'high' : cohesion >= 0.65 ? 'medium' : 'low';
    const sharedCount = new Map<string, SharedIndicator & { messages: Set<string> }>();
    for (const e of internal) for (const s of e.shared) {
      const k = `${s.family}|${s.value}`;
      const cur = sharedCount.get(k) ?? { ...s, messages: new Set<string>() };
      cur.messages.add(e.a);
      cur.messages.add(e.b);
      sharedCount.set(k, cur);
    }
    const sharedIndicators = [...sharedCount.values()]
      .map(({ messages: msgs, ...s }) => ({ ...s, messages: msgs.size }))
      .sort((x, y) => y.strength * y.messages - x.strength * x.messages)
      .slice(0, 25);
    const times = ids.map((id) => byId.get(id)?.time ?? null).filter((t): t is number => t !== null && t > 0);
    clusters.push({
      id: 'CL-' + createHash('sha256').update(ids.join('|')).digest('hex').slice(0, 8).toUpperCase(),
      members,
      cohesion: Math.round(cohesion * 1000) / 1000,
      density: Math.round(density * 1000) / 1000,
      exactEdges,
      confidence,
      label: clusterLabel(fps, verdict),
      verdict,
      firstSeen: times.length ? Math.min(...times) : null,
      lastSeen: times.length ? Math.max(...times) : null,
      profile,
      sharedIndicators,
    });
  }
  clusters.sort((x, y) => y.members.length - x.members.length || x.id.localeCompare(y.id));
  return {
    edges,
    clusters,
    stats: {
      messages: messages.length,
      candidatePairs,
      edges: edges.length,
      exactEdges: edges.filter((e) => e.tier === 'exact').length,
      clusters: clusters.length,
      clusteredMessages: clusters.reduce((s, c) => s + c.members.length, 0),
      ms: Math.round(performance.now() - t0),
    },
  };
}

function components(nodes: string[], edges: PairEvidence[]): Map<string, number> {
  const parent = new Map(nodes.map((n) => [n, n]));
  const find = (x: string): string => {
    let r = x;
    while (parent.get(r) !== r) r = parent.get(r) as string;
    parent.set(x, r);
    return r;
  };
  for (const e of edges) {
    const ra = find(e.a);
    const rb = find(e.b);
    if (ra !== rb) parent.set(ra, rb);
  }
  const ids = new Map<string, number>();
  const out = new Map<string, number>();
  for (const n of [...nodes].sort()) {
    const r = find(n);
    if (!ids.has(r)) ids.set(r, ids.size);
    out.set(n, ids.get(r) as number);
  }
  return out;
}

const INTENT_LABEL: Record<string, string> = {
  credential: 'credential lure', payment: 'payment fraud', giftcard: 'gift-card scam', crypto: 'crypto theft', mfa: 'MFA-code theft',
  delivery: 'delivery scam', document: 'fake shared document', tax: 'tax / government lure', job: 'job scam', reward: 'prize lure',
  extortion: 'extortion', callback: 'call-back scam', bec: 'business email compromise',
};

function mode<T>(values: (T | null | undefined)[]): T | null {
  const counts = new Map<T, number>();
  for (const v of values) if (v !== null && v !== undefined) counts.set(v, (counts.get(v) ?? 0) + 1);
  let best: T | null = null;
  let n = 0;
  for (const [v, c] of counts) if (c > n) [best, n] = [v, c];
  return best;
}

export function clusterLabel(fps: Fingerprint[], verdict: ClusterResult['verdict']): string {
  const brand = mode(fps.map((f) => f.content.brand));
  const intent = mode(fps.map((f) => f.content.intent));
  const brandName = brand ? (brandById(brand)?.name ?? brand) : null;
  if (intent && verdict !== 'bulk') return `${brandName ? brandName + ' ' : ''}${INTENT_LABEL[intent] ?? intent}`.replace(/^./, (c) => c.toUpperCase());
  const sender = mode(fps.map((f) => f.sender.displayName)) ?? mode(fps.map((f) => f.sender.fromOrg));
  if (verdict === 'bulk') return `Bulk mail · ${sender ?? brandName ?? 'unknown sender'}`;
  if (brandName) return `${brandName} impersonation`;
  const subject = mode(fps.map((f) => f.content.subjectTemplate));
  return subject ? `“${subject.slice(0, 60)}${subject.length > 60 ? '…' : ''}”` : 'Unlabelled cluster';
}
