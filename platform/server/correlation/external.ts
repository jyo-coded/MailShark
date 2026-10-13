// External correlation: message indicators against the intelligence store.
//   indicator listings  → "this URL / domain / hash / IP is listed by <source>" (exact after normalisation)
//   event records       → "indicators of this message appear in <source> event <name>"
// An event association is an evidence-based assessment, not ground truth:
//   reported-association  at least one strong, specific indicator is listed in the event
//   possible-association  only weak overlaps (parent domain, IP, subject line, file name)
import type { IntelStore, IntelHit, EventHit, MatchType } from '../intel/store';
import type { CorrObservation } from './engine';

export interface ExternalMatch {
  messageId: string;
  indicatorType: string;
  value: string;
  role: string;
  source: string;
  matchType: MatchType;
  matchedValue: string;
  record: Omit<IntelHit, 'source' | 'matchType' | 'value' | 'type'>;
  eventId: string | null;
  strength: number;
  suppressed: string | null;
  contextOnly: boolean;
}

export interface ExternalCampaign {
  source: string;
  eventId: string;
  name: string;
  org: string | null;
  date: number | null;
  updatedAt: number | null;
  tags: string[];
  reference: string | null;
  threatLevel: number | null;
  assessment: 'reported-association' | 'possible-association';
  confidence: 'high' | 'medium' | 'low';
  messages: string[];
  indicators: { type: string; value: string; matchType: MatchType; strength: number; roles: string[]; messages: number; toIds: boolean }[];
  rationale: string[];
  /** Ids of all records merged into this one when the source publishes numbered/dated series. */
  seriesEventIds?: string[];
  /** The record is a generic indicator dump rather than a named operation. */
  generic?: boolean;
}

const DATE_RE = /\b(?:\d{4}-\d{2}-\d{2}|\d{1,2}[./-]\d{1,2}[./-]\d{2,4}|(?:jan|feb|mar|apr|may|jun|jul|aug|sep|sept|oct|nov|dec)[a-z]*\.? \d{1,2},? \d{4}|\d{1,2} (?:jan|feb|mar|apr|may|jun|jul|aug|sep|sept|oct|nov|dec)[a-z]*,? \d{4})\b/gi;
const PART_RE = /\bpart \d+\s*(?:\/|of)\s*\d+\b/gi;

/** Name with dates, part counters and numbers removed: records of one generated series share it. */
export function seriesKey(name: string): string {
  return name
    .toLowerCase()
    .replace(DATE_RE, ' ')
    .replace(PART_RE, ' ')
    .replace(/[#\d]+/g, ' ')
    .replace(/[|:()[\]_,.-]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function seriesLabel(name: string): string {
  const s = name
    .replace(DATE_RE, '')
    .replace(PART_RE, '')
    .replace(/(\s*\|\s*)+/g, ' | ')
    .replace(/^\s*\|\s*|\s*\|\s*$/g, '')
    .replace(/\s+/g, ' ')
    .trim();
  return s || name;
}

const GENERIC_WORDS = new Set(['phishing', 'phish', 'malware', 'spam', 'scam', 'scams', 'ioc', 'iocs', 'indicators', 'indicator', 'feed', 'feeds', 'daily', 'weekly', 'monthly', 'blocklist', 'blacklist', 'list', 'urls', 'url', 'domains', 'domain', 'ips', 'ip', 'hashes', 'threat', 'threats', 'intel', 'osint', 'collection', 'dump', 'export', 'update', 'misc', 'various', 'automated', 'auto', 'generated', 'new', 'latest', 'and', 'of', 'the', 'from', 'sites', 'websites', 'links', 'reported', 'suspicious', 'malicious']);

/** True when a record's name only describes a category of data (no campaign, actor or lure). */
export function isGenericName(name: string): boolean {
  const words = seriesKey(name).split(' ').filter(Boolean);
  return words.length > 0 && words.every((w) => GENERIC_WORDS.has(w));
}

const HASH = new Set(['md5', 'sha1', 'sha256']);
const CONTEXT_ONLY_THREATS = new Set(['tor-exit']);

export function matchStrength(type: string, matchType: MatchType, suppressed: string | null, threat: string | null = null): number {
  if (suppressed || (threat && CONTEXT_ONLY_THREATS.has(threat))) return 0;
  switch (matchType) {
    case 'exact-url':
      return 0.95;
    case 'url-without-query':
      return 0.85;
    case 'host':
      return 0.85;
    case 'parent-domain':
      return 0.7;
    case 'host-of-listed-url':
      return 0.4;
    case 'cidr':
      return 0.5;
    case 'exact':
      if (HASH.has(type)) return 0.98;
      if (type === 'email' || type === 'phone' || type === 'btc') return 0.9;
      if (type === 'ip') return 0.7;
      if (type === 'subject') return 0.3;
      if (type === 'filename') return 0.2;
      return 0.6;
  }
}

interface Lookup {
  intelType: 'url' | 'domain' | 'ip' | 'email' | 'md5' | 'sha1' | 'sha256' | 'phone' | 'btc' | 'subject' | 'filename';
  value: string;
}

/** Which intelligence lookups an observation warrants (relay hops, recipients and the like are not looked up). */
function lookupsFor(o: CorrObservation): Lookup[] {
  const r = o.role;
  switch (o.type) {
    case 'url':
      return r === 'link' || r === 'qr-link' || r === 'attachment-link' ? [{ intelType: 'url', value: o.value }] : [];
    case 'hostname':
      return r === 'link-host' ? [{ intelType: 'domain', value: o.value }] : [];
    case 'domain':
      return r === 'from' || r === 'reply-to' || r === 'return-path' ? [{ intelType: 'domain', value: o.value }] : [];
    case 'email':
      return ['from', 'reply-to', 'return-path', 'authenticated-sender', 'display-name-address'].includes(r) ? [{ intelType: 'email', value: o.value }] : [];
    case 'ipv4':
    case 'ipv6':
      return r === 'origin-ip' || r === 'client-ip' || r === 'link-host' ? [{ intelType: 'ip', value: o.value }] : [];
    case 'sha256':
    case 'sha1':
    case 'md5':
      return r === 'attachment' ? [{ intelType: o.type, value: o.value }] : [];
    case 'phone':
      return [{ intelType: 'phone', value: o.value }];
    case 'btc':
      return [{ intelType: 'btc', value: o.value }];
    case 'filename':
      return r === 'attachment-name' ? [{ intelType: 'filename', value: o.value.toLowerCase() }] : [];
    default:
      return [];
  }
}

export function externalMatches(store: IntelStore, observations: CorrObservation[], subjects: Map<string, string> = new Map()): { matches: ExternalMatch[]; campaigns: ExternalCampaign[] } {
  const hitCache = new Map<string, IntelHit[]>();
  const eventCache = new Map<string, EventHit[]>();
  const matches: ExternalMatch[] = [];
  const events = new Map<string, { hit: EventHit; inds: Map<string, ExternalCampaign['indicators'][number] & { msgSet: Set<string> }>; messages: Set<string> }>();

  const listingHits = (l: Lookup): IntelHit[] => {
    const key = `${l.intelType}|${l.value}`;
    const cached = hitCache.get(key);
    if (cached) return cached;
    let hits: IntelHit[] = [];
    if (l.intelType === 'url') {
      hits = store.lookupUrl(l.value);
      if (!hits.length) {
        try {
          hits = store.listedUrlsOnHost(new URL(l.value).hostname, 3);
        } catch {
          hits = [];
        }
      }
    } else if (l.intelType === 'domain') hits = store.lookupHost(l.value);
    else if (l.intelType === 'ip') hits = store.lookupIp(l.value);
    else if (l.intelType === 'email' || l.intelType === 'phone' || l.intelType === 'btc' || HASH.has(l.intelType)) hits = store.lookupExact(l.intelType as 'email', l.value);
    hitCache.set(key, hits);
    return hits;
  };
  const eventHits = (l: Lookup): EventHit[] => {
    const key = `${l.intelType}|${l.value}`;
    const cached = eventCache.get(key);
    if (cached) return cached;
    const hits = store.lookupEvents(l.intelType, l.value);
    eventCache.set(key, hits);
    return hits;
  };
  const recordEvent = (messageId: string, role: string, h: EventHit): void => {
    const strength = matchStrength(h.type, h.matchType, h.suppressed);
    const key = `${h.source}|${h.eventId}`;
    let e = events.get(key);
    if (!e) events.set(key, (e = { hit: h, inds: new Map(), messages: new Set() }));
    const ik = `${h.type}|${h.value}`;
    const cur = e.inds.get(ik) ?? { type: h.type, value: h.value, matchType: h.matchType, strength, roles: [], messages: 0, toIds: h.toIds, msgSet: new Set<string>() };
    if (!cur.roles.includes(role)) cur.roles.push(role);
    cur.msgSet.add(messageId);
    cur.strength = Math.max(cur.strength, strength);
    e.inds.set(ik, cur);
    if (strength > 0) e.messages.add(messageId);
  };

  for (const o of observations) {
    for (const l of lookupsFor(o)) {
      if (l.intelType !== 'filename') {
        for (const h of listingHits(l)) {
          const strength = matchStrength(h.type === 'cidr' ? 'ip' : l.intelType, h.matchType, h.suppressed, h.threat);
          matches.push({
            messageId: o.messageId,
            indicatorType: o.type,
            value: o.value,
            role: o.role,
            source: h.source,
            matchType: h.matchType,
            matchedValue: h.value,
            record: { firstSeen: h.firstSeen, lastSeen: h.lastSeen, threat: h.threat, family: h.family, tags: h.tags, confidence: h.confidence, reference: h.reference, externalId: h.externalId, suppressed: h.suppressed },
            eventId: null,
            strength,
            suppressed: h.suppressed,
            contextOnly: !!h.threat && CONTEXT_ONLY_THREATS.has(h.threat),
          });
        }
      }
      for (const h of eventHits(l)) recordEvent(o.messageId, o.role, h);
    }
  }
  for (const [messageId, subject] of subjects) {
    const v = subject.toLowerCase().replace(/\s+/g, ' ').trim();
    if (v.length >= 8) for (const h of eventHits({ intelType: 'subject', value: v })) recordEvent(messageId, 'subject', h);
  }

  // Automatically generated record series (e.g. daily "Phishing | <date> | Part 12/566" pulses) are
  // merged into one record; series that do not name an operation are listings, not campaigns.
  const groups = new Map<string, { hit: EventHit; ids: string[]; dates: number[]; inds: Map<string, ExternalCampaign['indicators'][number] & { msgSet: Set<string> }>; messages: Set<string> }>();
  for (const { hit, inds, messages } of events.values()) {
    const key = `${hit.source}|${seriesKey(hit.name)}`;
    const g = groups.get(key);
    if (!g) {
      groups.set(key, { hit, ids: [hit.eventId], dates: hit.date ? [hit.date] : [], inds: new Map(inds), messages: new Set(messages) });
      continue;
    }
    g.ids.push(hit.eventId);
    if (hit.date) g.dates.push(hit.date);
    for (const m of messages) g.messages.add(m);
    for (const [k, i] of inds) {
      const cur = g.inds.get(k);
      if (!cur) g.inds.set(k, { ...i, msgSet: new Set(i.msgSet) });
      else {
        cur.strength = Math.max(cur.strength, i.strength);
        for (const r of i.roles) if (!cur.roles.includes(r)) cur.roles.push(r);
        for (const m of i.msgSet) cur.msgSet.add(m);
      }
    }
  }

  const campaigns: ExternalCampaign[] = [];
  for (const { hit, ids, dates, inds, messages } of groups.values()) {
    const list = [...inds.values()].map(({ msgSet, ...i }) => ({ ...i, messages: msgSet.size })).sort((a, b) => b.strength - a.strength);
    const max = list[0]?.strength ?? 0;
    if (max < 0.3) continue; // only suppressed / trivial overlaps: not an association
    const generic = isGenericName(hit.name);
    const strongTypes = new Set(list.filter((i) => i.strength >= 0.85).map((i) => i.type));
    const assessment: ExternalCampaign['assessment'] = max >= 0.85 && !generic ? 'reported-association' : 'possible-association';
    const confidence: ExternalCampaign['confidence'] = generic ? 'low' : strongTypes.size >= 2 ? 'high' : max >= 0.85 ? 'medium' : 'low';
    const series = ids.length > 1;
    const rationale = [
      `${list.filter((i) => i.strength > 0).length} indicator(s) from ${messages.size} message(s) appear in ${series ? `${ids.length} records of this ${hit.source} series` : `this ${hit.source} record`}.`,
      generic
        ? 'The record is a generic, automatically generated indicator list, not a named campaign: the overlap shows the indicator is known to the source, not which operation it belongs to.'
        : assessment === 'reported-association'
          ? `The strongest overlap is a specific artifact (${list[0]?.type} via ${list[0]?.matchType}).`
          : 'Only weak overlaps (parent domain, IP address, subject or file name): treat as a lead, not an attribution.',
      ...(list.some((i) => i.strength === 0) ? ['Some overlaps were not counted (popular or shared infrastructure).'] : []),
    ];
    const first = dates.length ? Math.min(...dates) : hit.date;
    const last = dates.length ? Math.max(...dates) : hit.date;
    campaigns.push({
      source: hit.source,
      eventId: hit.eventId,
      name: series ? `${seriesLabel(hit.name)} (series of ${ids.length} records)` : hit.name,
      org: hit.org,
      date: first,
      updatedAt: series ? last : hit.updatedAt,
      tags: hit.tags,
      reference: hit.reference,
      threatLevel: hit.threatLevel,
      assessment,
      confidence,
      messages: [...messages].sort(),
      indicators: list.slice(0, 50),
      rationale,
      ...(series ? { seriesEventIds: ids.slice(0, 200) } : {}),
      ...(generic ? { generic: true } : {}),
    });
  }
  campaigns.sort((a, b) => (a.assessment === b.assessment ? b.messages.length - a.messages.length : a.assessment === 'reported-association' ? -1 : 1));
  return { matches, campaigns };
}
