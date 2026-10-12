// The forensic report model: ONE object, built from stored results, from which the JSON, Markdown
// and DOCX renderings are produced (so the formats cannot disagree). Observed facts, analytical
// findings and external intelligence are kept in separate sections. Schema: ./schema.ts.
import { createHash, randomUUID } from 'node:crypto';
import type { AppContext } from '../context';
import { PLATFORM_VERSION } from '../context';
import type { Report } from '../../../engine/src/types';
import { findingDoc } from '../../../engine/src/catalog';
import { loadReport, intelMatchesFor, type MessageRow } from '../api/messages';

export const REPORT_SCHEMA_VERSION = 'mailshark.forensic-report/1.0.0';

export type ReportScope = { kind: 'case' } | { kind: 'batch'; batchId: string } | { kind: 'messages'; ids: string[] };

export interface ForensicReport {
  schema: typeof REPORT_SCHEMA_VERSION;
  report: {
    id: string;
    generatedAt: string;
    generatedBy: { id: string; username: string; displayName: string };
    platform: { name: 'MailShark Forensic Platform'; version: string };
    scope: { kind: ReportScope['kind']; reference: string | null; description: string };
  };
  case: { id: string; name: string; reference: string | null; description: string | null; status: string; createdAt: string; legalHold: boolean; retentionUntil: string | null; onlineLookupsEnabled: boolean };
  provenance: {
    engineVersions: string[];
    configHashes: string[];
    intelSnapshots: string[];
    intelligenceSources: { id: string; name: string; provider: string; kind: string; attribution: string; status: string; lastSuccess: string | null; records: number; events: number; snapshotSha256: string | null; license: string }[];
    onlineLookups: { at: string; by: string | null; indicator: string; sources: unknown }[];
    correlation: { correlatedAt: string | null; version: number; method: string };
  };
  statistics: {
    evidenceFiles: number;
    evidenceBytes: number;
    rejectedFiles: number;
    duplicateFiles: number;
    messages: number;
    analyzed: number;
    failed: number;
    pending: number;
    duplicateMessages: number;
    byClass: Record<string, number>;
    bySeverity: Record<string, number>;
    withIntelMatches: number;
    clusters: number;
    threatClusters: number;
    externalAssociations: number;
  };
  evidence: {
    id: string;
    originalName: string;
    sha256: string | null;
    sha1: string | null;
    md5: string | null;
    size: number;
    format: string | null;
    status: string;
    receivedAt: string;
    uploadedBy: string | null;
    batchId: string;
    duplicateOf: string | null;
    messageCount: number;
    error: { code: string; detail: string | null } | null;
  }[];
  messages: ReportMessage[];
  campaigns: {
    clusters: {
      id: string;
      label: string;
      verdict: string;
      confidence: string;
      size: number;
      cohesion: number;
      density: number;
      exactRelationships: number;
      firstSeen: string | null;
      lastSeen: string | null;
      method: string;
      members: { messageId: string; strength: number }[];
      invariants: { attribute: string; values: string[] }[];
      rotated: { attribute: string; values: string[] }[];
      sharedIndicators: { family: string; type: string; value: string; strength: number; messages: number; discounts: string[] }[];
      relationships: { a: string; b: string; tier: string; score: number; indicatorScore: number; similarity: number; hardLink: string | null; sharedIndicators: { family: string; value: string; strength: number }[] }[];
      externalAssociations: { source: string; eventId: string; name: string; assessment: string; confidence: string; overlap: number }[];
    }[];
    external: {
      source: string;
      eventId: string;
      name: string;
      organisation: string | null;
      date: string | null;
      reference: string | null;
      assessment: string;
      confidence: string;
      messages: string[];
      matchedIndicators: { type: string; value: string; matchType: string; strength: number; roles: string[] }[];
      rationale: string[];
      tags: string[];
    }[];
  };
  limitations: string[];
  integrity: { hashAlgorithm: 'SHA-256'; dataSha256: string; note: string };
}

export interface ReportMessage {
  id: string;
  evidenceId: string;
  derivation: string;
  containerIndex: number;
  byteOffset: number | null;
  sha256: string;
  size: number;
  status: string;
  duplicateOf: string | null;
  summary: { subject: string | null; from: string | null; fromName: string | null; to: string | null; date: string | null; messageId: string | null };
  classification: { class: string | null; severity: string | null; confidence: string | null; riskScore: number | null; evidenceCoverage: number | null; rationale: string[]; thresholds: unknown } | null;
  observations: {
    authentication: { source: string; reportedBy: string | null; spf: string; dkim: string; dmarc: string; arc: string; dmarcPolicy: string | null } | null;
    route: { originIp: string | null; originHost: string | null; originAsn: { asn: number; name: string | null } | null; receiver: string | null; hops: { from: string | null; ip: string | null; by: string | null; at: string | null; verified: boolean }[] } | null;
    dkim: { domain: string; selector: string; algorithm: string; bodyHash: string; signature: string; detail: string }[];
    originating: Record<string, string | null> | null;
    coverage: { layer: string; status: string; note: string }[];
  } | null;
  findings: {
    id: string;
    title: string;
    category: string;
    severity: string;
    weight: number;
    method: string | null;
    detail: string;
    rationale: string | null;
    evidence: { label: string; value: string }[];
    components: string[];
    limitations: string | null;
    recommendedActions: string[];
    attack: { id: string; name: string }[];
  }[];
  indicators: { type: string; value: string; role: string; component: string; context: string | null; suspicious: boolean }[];
  intelligence: { source: string; indicatorType: string; indicator: string; matchType: string; matchedValue: string; strength: number; firstSeen: string | null; lastSeen: string | null; threat: string | null; family: string | null; reference: string | null; suppressed: string | null }[];
  campaign: { clusterId: string; label: string } | null;
  processing: { analyzedAt: string | null; engineVersion: string | null; configHash: string | null; intelSnapshot: string | null; durationMs: number | null; resultSha256: string | null; attempts: number; history: { at: string; event: string; detail: unknown }[] };
  error: { code: string; detail: string | null } | null;
}

const iso = (t: number | null | undefined): string | null => (t ? new Date(t).toISOString() : null);

export const GENERAL_LIMITATIONS = [
  'Analysis is static: attachments are inspected as bytes and never opened or executed; links are analysed lexically and never visited. Payloads that only reveal themselves when run or rendered are not observed.',
  'Authentication verdicts come from Authentication-Results headers that can be attributed to the receiving organisation; where they cannot, they are reported as unverified. Absence of such headers is unavailable evidence, not a failure.',
  'DKIM header signatures, when checked, use the key published at analysis time. Keys rotated or revoked since delivery make genuine old signatures unverifiable.',
  'Hops in the Received chain below the receiving organisation’s hand-off were written by the sending side and may be forged.',
  'Threat-intelligence matches reflect the listing sources at the recorded snapshot. Absence from every source is not evidence that an indicator is safe.',
  'Campaign clusters and external associations are evidence-based assessments from shared artifacts and similarity, not proof of common authorship; each relationship lists the evidence that supports it.',
  'The risk score is an ordinal measure of accumulated evidence, not a probability. Precision and recall of the classification on public corpora are documented in the platform validation report.',
  'This platform has not been evaluated for conformity with ISO/IEC 27037, NIST SP 800-86 or any accreditation scheme; admissibility is a matter for the examiner and the jurisdiction.',
];

function messageIdsForScope(ctx: AppContext, caseId: string, scope: ReportScope): string[] {
  if (scope.kind === 'messages') {
    const ok = new Set(ctx.db.all<{ id: string }>('SELECT id FROM messages WHERE case_id = ?', caseId).map((r) => r.id));
    return scope.ids.filter((id) => ok.has(id));
  }
  if (scope.kind === 'batch') return ctx.db.all<{ id: string }>('SELECT m.id FROM messages m JOIN evidence e ON e.id = m.evidence_id WHERE m.case_id = ? AND e.batch_id = ? ORDER BY e.original_name, m.container_index', caseId, scope.batchId).map((r) => r.id);
  return ctx.db.all<{ id: string }>('SELECT m.id FROM messages m JOIN evidence e ON e.id = m.evidence_id WHERE m.case_id = ? ORDER BY e.received_at, e.original_name, m.container_index', caseId).map((r) => r.id);
}

function buildMessage(ctx: AppContext, caseId: string, m: MessageRow): ReportMessage {
  const loaded = m.status === 'analyzed' ? loadReport(ctx, m.id) : null;
  const r: Report | null = loaded?.report ?? null;
  const history = ctx.db.all<{ ts: number; kind: string; detail: string | null }>("SELECT ts, kind, detail FROM events WHERE subject_type = 'message' AND subject_id = ? ORDER BY ts", m.id).map((h) => ({ at: iso(h.ts) as string, event: h.kind, detail: h.detail ? (JSON.parse(h.detail) as unknown) : null }));
  const cluster = m.cluster_id ? ctx.db.get<{ id: string; label: string }>('SELECT id, label FROM clusters WHERE id = ?', m.cluster_id) ?? null : null;
  const asn = r?.route.originIp ? ctx.intel.store.asn(r.route.originIp) : null;
  return {
    id: m.id,
    evidenceId: m.evidence_id,
    derivation: m.derivation,
    containerIndex: m.container_index,
    byteOffset: m.byte_offset,
    sha256: m.sha256,
    size: m.size,
    status: m.status,
    duplicateOf: m.duplicate_of,
    summary: { subject: m.subject, from: m.from_addr, fromName: m.from_name, to: m.to_addr, date: iso(m.sent_at), messageId: m.message_id },
    classification: r?.classification
      ? { class: r.classification.class, severity: r.classification.severity, confidence: r.classification.confidence, riskScore: r.score, evidenceCoverage: r.coverage?.score ?? null, rationale: r.classification.rationale, thresholds: r.classification.thresholds }
      : m.status === 'failed'
        ? { class: 'failed', severity: null, confidence: null, riskScore: null, evidenceCoverage: null, rationale: [`Analysis failed: ${m.error_code ?? 'error'}`], thresholds: null }
        : null,
    observations: r
      ? {
          authentication: { source: r.auth.source, reportedBy: r.auth.authServId, spf: r.auth.spf, dkim: r.auth.dkim, dmarc: r.auth.dmarc, arc: r.auth.arc, dmarcPolicy: r.auth.dmarcPolicy },
          route: {
            originIp: r.route.originIp,
            originHost: r.route.originHost,
            originAsn: asn,
            receiver: r.route.receiverOrg,
            hops: r.route.hops.map((h) => ({ from: h.fromRdns ?? h.fromHost, ip: h.fromIp, by: h.byHost, at: iso(h.timestamp), verified: h.trusted })),
          },
          dkim: (r.dkim ?? []).map((d) => ({ domain: d.domain, selector: d.selector, algorithm: d.algorithm, bodyHash: d.bodyHash, signature: d.signature, detail: d.detail })),
          originating: r.forensics ? (r.forensics.originating as unknown as Record<string, string | null>) : null,
          coverage: (r.coverage?.layers ?? []).map((l) => ({ layer: l.label, status: l.status, note: l.note })),
        }
      : null,
    findings: (r?.findings ?? []).map((f) => {
      const doc = findingDoc(f.id);
      return {
        id: f.id,
        title: f.title,
        category: f.category,
        severity: f.severity,
        weight: f.weight,
        method: doc?.method ?? null,
        detail: f.detail,
        rationale: doc?.rationale ?? null,
        evidence: (f.evidence ?? []).map((e) => ({ label: e.label, value: e.value })),
        components: f.refs ?? [],
        limitations: doc?.limitations ?? null,
        recommendedActions: doc?.actions ?? [],
        attack: doc?.attack ?? [],
      };
    }),
    indicators: (r?.iocs ?? []).map((i) => ({ type: i.type, value: i.value, role: i.role, component: i.ref, context: i.context ?? null, suspicious: !!i.suspicious })),
    intelligence: intelMatchesFor(ctx, caseId, m.id).map((x) => {
      const rec = x['record'] as { firstSeen?: number | null; lastSeen?: number | null; threat?: string | null; family?: string | null; reference?: string | null; suppressed?: string | null };
      return {
        source: x['source'] as string,
        indicatorType: x['indicatorType'] as string,
        indicator: x['indicator'] as string,
        matchType: x['matchType'] as string,
        matchedValue: x['matchedValue'] as string,
        strength: x['strength'] as number,
        firstSeen: iso(rec.firstSeen),
        lastSeen: iso(rec.lastSeen),
        threat: rec.threat ?? null,
        family: rec.family ?? null,
        reference: rec.reference ?? null,
        suppressed: rec.suppressed ?? null,
      };
    }),
    campaign: cluster ? { clusterId: cluster.id, label: cluster.label } : null,
    processing: {
      analyzedAt: iso(m.analyzed_at),
      engineVersion: loaded?.meta.engine_version ?? null,
      configHash: loaded?.meta.config_hash ?? null,
      intelSnapshot: loaded?.meta.intel_snapshot ?? null,
      durationMs: loaded?.meta.duration_ms ?? null,
      resultSha256: loaded?.meta.report_sha256 ?? null,
      attempts: m.attempts,
      history,
    },
    error: m.error_code ? { code: m.error_code, detail: m.error_detail } : null,
  };
}

/** Canonical JSON (sorted keys) so that the data hash does not depend on property order. */
export function canonicalJson(v: unknown): string {
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(canonicalJson).join(',')}]`;
  const o = v as Record<string, unknown>;
  return `{${Object.keys(o)
    .filter((k) => o[k] !== undefined)
    .sort()
    .map((k) => `${JSON.stringify(k)}:${canonicalJson(o[k])}`)
    .join(',')}}`;
}

export function buildReport(ctx: AppContext, caseId: string, scope: ReportScope, user: { id: string; username: string; display_name: string }): ForensicReport {
  const c = ctx.db.get<{ id: string; name: string; reference: string | null; description: string | null; status: string; created_at: number; legal_hold: number; retention_until: number | null; online_lookups: number; correlated_at: number | null; correlation_version: number }>('SELECT * FROM cases WHERE id = ?', caseId);
  if (!c) throw new Error('case not found');
  const ids = messageIdsForScope(ctx, caseId, scope);
  const idSet = new Set(ids);
  const rows = ids.map((id) => ctx.db.get<MessageRow>('SELECT * FROM messages WHERE id = ?', id)).filter((m): m is MessageRow => !!m);
  const messages = rows.map((m) => buildMessage(ctx, caseId, m));
  const evidenceIds = new Set(rows.map((m) => m.evidence_id));
  const evRows = ctx.db.all<{ id: string; original_name: string; sha256: string; sha1: string; md5: string; size: number; format: string | null; status: string; received_at: number; uploaded_by: string; batch_id: string; duplicate_of: string | null; message_count: number; error_code: string | null; error_detail: string | null }>(
    scope.kind === 'batch' ? 'SELECT * FROM evidence WHERE case_id = ? AND batch_id = ? ORDER BY received_at, original_name' : 'SELECT * FROM evidence WHERE case_id = ? ORDER BY received_at, original_name',
    caseId,
    ...(scope.kind === 'batch' ? [scope.batchId] : []),
  ).filter((e) => scope.kind !== 'messages' || evidenceIds.has(e.id));
  const users = new Map(ctx.auth.users().map((u) => [u.id, u.username]));

  const clusterRows = ctx.db.all<{ id: string; label: string; verdict: string; confidence: string; size: number; cohesion: number; first_seen: number | null; last_seen: number | null; profile_json: string; external_json: string; method: string }>('SELECT * FROM clusters WHERE case_id = ?', caseId);
  const clusters = clusterRows
    .map((cl) => {
      const p = JSON.parse(cl.profile_json) as {
        members: { id: string; strength: number }[];
        density: number;
        exactEdges: number;
        profile: { invariants: { label: string; values: string[] }[]; rotated: { label: string; values: string[] }[] };
        sharedIndicators: { family: string; type: string; value: string; strength: number; messages: number; discounts: string[] }[];
      };
      const members = p.members.filter((mm) => idSet.has(mm.id));
      if (!members.length) return null;
      const memberSet = new Set(p.members.map((mm) => mm.id));
      const relationships = ctx.db
        .all<{ a: string; b: string; tier: string; score: number; evidence_json: string }>('SELECT a, b, tier, score, evidence_json FROM edges WHERE case_id = ?', caseId)
        .filter((e) => memberSet.has(e.a) && memberSet.has(e.b))
        .map((e) => {
          const ev = JSON.parse(e.evidence_json) as { indicatorScore: number; similarity: number; hardLink: string | null; shared: { family: string; value: string; strength: number }[] };
          return { a: e.a, b: e.b, tier: e.tier, score: e.score, indicatorScore: ev.indicatorScore, similarity: ev.similarity, hardLink: ev.hardLink, sharedIndicators: ev.shared.slice(0, 10).map((s) => ({ family: s.family, value: s.value, strength: s.strength })) };
        });
      return {
        id: cl.id,
        label: cl.label,
        verdict: cl.verdict,
        confidence: cl.confidence,
        size: cl.size,
        cohesion: cl.cohesion,
        density: p.density,
        exactRelationships: p.exactEdges,
        firstSeen: iso(cl.first_seen),
        lastSeen: iso(cl.last_seen),
        method: cl.method,
        members: p.members.map((mm) => ({ messageId: mm.id, strength: mm.strength })),
        invariants: p.profile.invariants.map((i) => ({ attribute: i.label, values: i.values })),
        rotated: p.profile.rotated.map((i) => ({ attribute: i.label, values: i.values })),
        sharedIndicators: p.sharedIndicators,
        relationships,
        externalAssociations: JSON.parse(cl.external_json) as ForensicReport['campaigns']['clusters'][number]['externalAssociations'],
      };
    })
    .filter((x): x is NonNullable<typeof x> => !!x);
  const external = ctx.db
    .all<{ source: string; event_id: string; name: string; assessment: string; confidence: string; detail_json: string }>('SELECT * FROM external_campaigns WHERE case_id = ?', caseId)
    .map((x) => {
      const d = JSON.parse(x.detail_json) as { messages: string[]; org: string | null; date: number | null; reference: string | null; indicators: { type: string; value: string; matchType: string; strength: number; roles: string[] }[]; rationale: string[]; tags: string[] };
      return { x, d, msgs: d.messages.filter((id) => idSet.has(id)) };
    })
    .filter((e) => e.msgs.length)
    .map(({ x, d, msgs }) => ({
      source: x.source,
      eventId: x.event_id,
      name: x.name,
      organisation: d.org,
      date: iso(d.date),
      reference: d.reference,
      assessment: x.assessment,
      confidence: x.confidence,
      messages: msgs,
      matchedIndicators: d.indicators.map((i) => ({ type: i.type, value: i.value, matchType: i.matchType, strength: i.strength, roles: i.roles })),
      rationale: d.rationale,
      tags: d.tags.slice(0, 30),
    }));

  const byClass: Record<string, number> = {};
  const bySeverity: Record<string, number> = {};
  for (const m of messages) {
    const k = m.classification?.class ?? (m.status === 'duplicate' ? 'duplicate' : m.status);
    byClass[k] = (byClass[k] ?? 0) + 1;
    const s = m.classification?.severity;
    if (s) bySeverity[s] = (bySeverity[s] ?? 0) + 1;
  }
  const sources = ctx.intel.sources().filter((s) => s.kind !== 'lookup' || s.freshness === 'available');
  const lookups = ctx.audit.list({ caseId, limit: 1000 }).filter((a) => a.action === 'intel.online-lookup').map((a) => {
    const d = a.details ? (JSON.parse(a.details) as { type?: string; value?: string; sources?: unknown }) : {};
    return { at: iso(a.ts) as string, by: a.username, indicator: `${d.type ?? ''}:${d.value ?? ''}`, sources: d.sources ?? null };
  });

  const limitations = [...GENERAL_LIMITATIONS];
  const inconclusive = byClass['inconclusive'] ?? 0;
  if (inconclusive) limitations.push(`${inconclusive} message(s) are inconclusive: the evidence needed to assess them (e.g. body text, authentication results, delivery path) was not present in the files provided.`);
  const failed = messages.filter((m) => m.status === 'failed');
  if (failed.length) limitations.push(`${failed.length} message(s) could not be analysed; their errors are listed per message.`);
  const stale = sources.filter((s) => s.kind !== 'lookup' && s.freshness !== 'current' && s.enabled);
  if (stale.length) limitations.push(`Intelligence sources not current at report time: ${stale.map((s) => `${s.name} (${s.freshness})`).join(', ')}.`);
  if (messages.some((m) => m.derivation === 'reconstructed-from-msg')) limitations.push('Some messages were reconstructed from Outlook .msg items; their MIME structure is synthetic and byte-level checks were not applied.');
  const pending = rows.filter((m) => m.status === 'queued' || m.status === 'running').length;
  if (pending) limitations.push(`${pending} message(s) were still being processed when this report was generated.`);

  const scopeDesc = scope.kind === 'case' ? 'Entire investigation' : scope.kind === 'batch' ? `Evidence batch ${scope.batchId}` : `${ids.length} selected message(s)`;
  const report: ForensicReport = {
    schema: REPORT_SCHEMA_VERSION,
    report: {
      id: randomUUID(),
      generatedAt: new Date().toISOString(),
      generatedBy: { id: user.id, username: user.username, displayName: user.display_name },
      platform: { name: 'MailShark Forensic Platform', version: PLATFORM_VERSION },
      scope: { kind: scope.kind, reference: scope.kind === 'batch' ? scope.batchId : null, description: scopeDesc },
    },
    case: { id: c.id, name: c.name, reference: c.reference, description: c.description, status: c.status, createdAt: iso(c.created_at) as string, legalHold: !!c.legal_hold, retentionUntil: iso(c.retention_until), onlineLookupsEnabled: !!c.online_lookups },
    provenance: {
      engineVersions: [...new Set(messages.map((m) => m.processing.engineVersion).filter((v): v is string => !!v))],
      configHashes: [...new Set(messages.map((m) => m.processing.configHash).filter((v): v is string => !!v))],
      intelSnapshots: [...new Set(messages.map((m) => m.processing.intelSnapshot).filter((v): v is string => !!v))],
      intelligenceSources: sources.map((s) => ({ id: s.id, name: s.name, provider: s.provider, kind: s.kind, attribution: s.attribution, status: s.freshness, lastSuccess: iso(s.lastSuccess), records: s.recordCount, events: s.eventCount, snapshotSha256: s.snapshotSha256, license: s.license })),
      onlineLookups: lookups,
      correlation: { correlatedAt: iso(c.correlated_at), version: c.correlation_version, method: 'Specificity-weighted shared indicators combined (noisy-OR) with layered fingerprint similarity; Louvain community detection; external matching against intelligence records.' },
    },
    statistics: {
      evidenceFiles: evRows.length,
      evidenceBytes: evRows.reduce((s, e) => s + e.size, 0),
      rejectedFiles: evRows.filter((e) => e.status === 'rejected').length,
      duplicateFiles: evRows.filter((e) => e.status === 'duplicate').length,
      messages: messages.length,
      analyzed: messages.filter((m) => m.status === 'analyzed').length,
      failed: failed.length,
      pending,
      duplicateMessages: messages.filter((m) => m.status === 'duplicate').length,
      byClass,
      bySeverity,
      withIntelMatches: messages.filter((m) => m.intelligence.some((i) => i.strength > 0)).length,
      clusters: clusters.length,
      threatClusters: clusters.filter((cl) => cl.verdict !== 'bulk').length,
      externalAssociations: external.filter((e) => e.assessment === 'reported-association').length,
    },
    evidence: evRows.map((e) => ({
      id: e.id,
      originalName: e.original_name,
      sha256: e.sha256 === '-' ? null : e.sha256,
      sha1: e.sha1 === '-' ? null : e.sha1,
      md5: e.md5 === '-' ? null : e.md5,
      size: e.size,
      format: e.format,
      status: e.status,
      receivedAt: iso(e.received_at) as string,
      uploadedBy: users.get(e.uploaded_by) ?? null,
      batchId: e.batch_id,
      duplicateOf: e.duplicate_of,
      messageCount: e.message_count,
      error: e.error_code ? { code: e.error_code, detail: e.error_detail } : null,
    })),
    messages,
    campaigns: { clusters, external },
    limitations,
    integrity: { hashAlgorithm: 'SHA-256', dataSha256: '', note: 'dataSha256 is the SHA-256 of the canonical JSON (sorted keys) of this report with integrity.dataSha256 set to an empty string. Every rendering (JSON, Markdown, DOCX) of the same report carries the same value.' },
  };
  report.integrity.dataSha256 = createHash('sha256').update(canonicalJson(report)).digest('hex');
  return report;
}

/** Recomputes a report's data hash (for verification by anyone holding the JSON). */
export function verifyReportHash(r: ForensicReport): boolean {
  const copy = JSON.parse(JSON.stringify(r)) as ForensicReport;
  const claimed = copy.integrity.dataSha256;
  copy.integrity.dataSha256 = '';
  return createHash('sha256').update(canonicalJson(copy)).digest('hex') === claimed;
}
