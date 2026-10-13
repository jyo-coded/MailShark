// Messages (analysis results), raw evidence view, indicators, search, progress, online lookups.
import { gunzipSync } from 'node:zlib';
import type { FastifyInstance } from 'fastify';
import type { AppContext } from '../context';
import type { Report } from '../../../engine/src/types';
import { findingDoc, type FindingDoc } from '../../../engine/src/catalog';
import { ApiError, audit, badRequest, int, list, notFound, requireCase, requireUser, str } from './util';
import { caseRole } from '../security/auth';
import type { IntelType } from '../intel/normalize';
import { registrable } from '../intel/normalize';

const CLASSES = ['malicious', 'suspicious', 'benign', 'inconclusive', 'failed'] as const;
const STATUSES = ['queued', 'running', 'analyzed', 'failed', 'duplicate'] as const;
const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info', 'none'] as const;
const SORTS: Record<string, string> = {
  received: 'm.created_at',
  sent: 'm.sent_at',
  score: 'm.score',
  class: "CASE m.class WHEN 'malicious' THEN 5 WHEN 'suspicious' THEN 4 WHEN 'inconclusive' THEN 3 WHEN 'failed' THEN 2 WHEN 'benign' THEN 1 ELSE 0 END",
  from: 'm.from_addr',
  subject: 'm.subject',
  findings: 'm.finding_count',
  intel: 'm.intel_hits',
  evidence: 'e.original_name',
};

const like = (s: string): string => `%${s.replace(/[\\%_]/g, (c) => '\\' + c)}%`;

export interface MessageRow {
  id: string;
  case_id: string;
  evidence_id: string;
  container_index: number;
  byte_offset: number | null;
  size: number;
  sha256: string;
  blob_store: 'evidence' | 'derived';
  derivation: string;
  status: string;
  duplicate_of: string | null;
  attempts: number;
  subject: string | null;
  from_addr: string | null;
  from_name: string | null;
  to_addr: string | null;
  sent_at: number | null;
  message_id: string | null;
  class: string | null;
  severity: string | null;
  confidence: string | null;
  score: number | null;
  coverage: number | null;
  verdict: string | null;
  finding_count: number;
  ioc_count: number;
  intel_hits: number;
  cluster_id: string | null;
  error_code: string | null;
  error_detail: string | null;
  created_at: number;
  analyzed_at: number | null;
  engine_version: string | null;
}

export function messageSummary(m: MessageRow & { original_name?: string; cluster_label?: string | null }): Record<string, unknown> {
  return {
    id: m.id,
    evidenceId: m.evidence_id,
    evidenceName: m.original_name ?? null,
    containerIndex: m.container_index,
    derivation: m.derivation,
    status: m.status,
    duplicateOf: m.duplicate_of,
    subject: m.subject,
    from: m.from_addr,
    fromName: m.from_name,
    to: m.to_addr,
    sentAt: m.sent_at,
    messageId: m.message_id,
    class: m.class,
    severity: m.severity,
    confidence: m.confidence,
    score: m.score,
    coverage: m.coverage,
    findingCount: m.finding_count,
    iocCount: m.ioc_count,
    intelHits: m.intel_hits,
    clusterId: m.cluster_id,
    clusterLabel: m.cluster_label ?? null,
    error: m.error_code ? { code: m.error_code, detail: m.error_detail } : null,
    receivedAt: m.created_at,
    analyzedAt: m.analyzed_at,
    size: m.size,
    sha256: m.sha256,
  };
}

export function loadReport(ctx: AppContext, messageId: string): { report: Report; meta: { report_sha256: string; engine_version: string; config_hash: string; intel_snapshot: string | null; options_json: string; duration_ms: number | null; created_at: number } } | null {
  const r = ctx.db.get<{ report_gz: Uint8Array; report_sha256: string; engine_version: string; config_hash: string; intel_snapshot: string | null; options_json: string; duration_ms: number | null; created_at: number }>('SELECT * FROM results WHERE message_id = ?', messageId);
  if (!r) return null;
  const report = JSON.parse(gunzipSync(Buffer.from(r.report_gz)).toString('utf8')) as Report;
  return { report, meta: { report_sha256: r.report_sha256, engine_version: r.engine_version, config_hash: r.config_hash, intel_snapshot: r.intel_snapshot, options_json: r.options_json, duration_ms: r.duration_ms, created_at: r.created_at } };
}

export function intelMatchesFor(ctx: AppContext, caseId: string, messageId: string): Record<string, unknown>[] {
  return ctx.db
    .all<{ source: string; match_type: string; matched_value: string; record_json: string; event_id: string | null; strength: number; matched_at: number; type: string; value: string }>(
      `SELECT im.source, im.match_type, im.matched_value, im.record_json, im.event_id, im.strength, im.matched_at, i.type, i.value
       FROM intel_matches im JOIN indicators i ON i.id = im.indicator_id WHERE im.case_id = ? AND im.message_id = ? ORDER BY im.strength DESC`,
      caseId,
      messageId,
    )
    .map((x) => ({ source: x.source, matchType: x.match_type, matchedValue: x.matched_value, indicatorType: x.type, indicator: x.value, strength: x.strength, matchedAt: x.matched_at, eventId: x.event_id, record: JSON.parse(x.record_json) as unknown }));
}

export function messageDetail(ctx: AppContext, caseId: string, messageId: string): Record<string, unknown> {
  let m = ctx.db.get<MessageRow>('SELECT * FROM messages WHERE id = ? AND case_id = ?', messageId, caseId);
  if (!m) throw notFound('Message not found.');
  const requested = m;
  if (m.status === 'duplicate' && m.duplicate_of) m = ctx.db.get<MessageRow>('SELECT * FROM messages WHERE id = ?', m.duplicate_of) ?? m;
  const ev = ctx.db.get<{ id: string; original_name: string; sha256: string; format: string | null; received_at: number; uploaded_by: string; batch_id: string }>('SELECT id, original_name, sha256, format, received_at, uploaded_by, batch_id FROM evidence WHERE id = ?', requested.evidence_id);
  const uploader = ev ? ctx.auth.user(ev.uploaded_by) : undefined;
  const loaded = m.status === 'analyzed' ? loadReport(ctx, m.id) : null;
  const docs: Record<string, FindingDoc> = {};
  for (const f of loaded?.report.findings ?? []) {
    const d = findingDoc(f.id);
    if (d) docs[f.id] = d;
  }
  const cluster = m.cluster_id ? ctx.db.get<{ id: string; label: string; confidence: string; size: number; verdict: string; cohesion: number }>('SELECT id, label, confidence, size, verdict, cohesion FROM clusters WHERE id = ?', m.cluster_id) ?? null : null;
  const related = ctx.db
    .all<{ other: string; tier: string; score: number; evidence_json: string }>(
      'SELECT CASE WHEN a = ? THEN b ELSE a END AS other, tier, score, evidence_json FROM edges WHERE case_id = ? AND (a = ? OR b = ?) ORDER BY score DESC LIMIT 50',
      m.id,
      caseId,
      m.id,
      m.id,
    )
    .map((e) => {
      const o = ctx.db.get<MessageRow>('SELECT * FROM messages WHERE id = ?', e.other);
      const evd = JSON.parse(e.evidence_json) as { shared: unknown[]; layers: unknown; hardLink: string | null; indicatorScore: number; similarity: number };
      return { message: o ? messageSummary(o) : { id: e.other }, tier: e.tier, score: e.score, shared: evd.shared.slice(0, 8), layers: evd.layers, hardLink: evd.hardLink, indicatorScore: evd.indicatorScore, similarity: evd.similarity };
    });
  const external = ctx.db
    .all<{ source: string; event_id: string; name: string; assessment: string; confidence: string; detail_json: string }>('SELECT source, event_id, name, assessment, confidence, detail_json FROM external_campaigns WHERE case_id = ?', caseId)
    .filter((x) => (JSON.parse(x.detail_json) as { messages: string[] }).messages.includes(m!.id))
    .map((x) => {
      const d = JSON.parse(x.detail_json) as { indicators: unknown[]; rationale: string[]; reference: string | null; date: number | null; org: string | null; tags: string[] };
      return { source: x.source, eventId: x.event_id, name: x.name, assessment: x.assessment, confidence: x.confidence, reference: d.reference, date: d.date, org: d.org, tags: d.tags.slice(0, 12), rationale: d.rationale, indicators: d.indicators.slice(0, 20) };
    });
  const history = ctx.db.all<{ ts: number; kind: string; detail: string | null }>("SELECT ts, kind, detail FROM events WHERE subject_type = 'message' AND subject_id IN (?, ?) ORDER BY ts", requested.id, m.id).map((h) => ({ ts: h.ts, kind: h.kind, detail: h.detail ? (JSON.parse(h.detail) as unknown) : null }));
  const duplicates = ctx.db.all<{ id: string; evidence_id: string }>("SELECT id, evidence_id FROM messages WHERE duplicate_of = ? AND case_id = ?", m.id, caseId);
  return {
    message: messageSummary(requested),
    analyzedAs: m.id !== requested.id ? m.id : null,
    provenance: ev
      ? {
          evidenceId: ev.id,
          evidenceName: ev.original_name,
          evidenceSha256: ev.sha256,
          format: ev.format,
          batchId: ev.batch_id,
          receivedAt: ev.received_at,
          uploadedBy: uploader?.username ?? null,
          derivation: requested.derivation,
          containerIndex: requested.container_index,
          byteOffset: requested.byte_offset,
          messageSha256: requested.sha256,
          messageSize: requested.size,
          storedAs: requested.blob_store,
        }
      : null,
    report: loaded?.report ?? null,
    processing: loaded
      ? { engineVersion: loaded.meta.engine_version, configHash: loaded.meta.config_hash, intelSnapshot: loaded.meta.intel_snapshot, durationMs: loaded.meta.duration_ms, reportSha256: loaded.meta.report_sha256, analyzedAt: loaded.meta.created_at, options: JSON.parse(loaded.meta.options_json) as unknown, attempts: m.attempts }
      : null,
    findingDocs: docs,
    intel: intelMatchesFor(ctx, caseId, m.id),
    cluster,
    related,
    externalCampaigns: external,
    history,
    duplicates,
  };
}

export function registerMessages(app: FastifyInstance, ctx: AppContext): void {
  app.get('/api/cases/:id/messages', async (req) => {
    const { id } = req.params as { id: string };
    requireCase(ctx, req, id);
    const q = req.query as Record<string, string | undefined>;
    const where: string[] = ['m.case_id = ?'];
    const params: (string | number)[] = [id];
    const classes = list(q['class'], CLASSES);
    if (classes.length) {
      where.push(`m.class IN (${classes.map(() => '?').join(',')})`);
      params.push(...classes);
    }
    const statuses = list(q['status'], STATUSES);
    if (statuses.length) {
      where.push(`m.status IN (${statuses.map(() => '?').join(',')})`);
      params.push(...statuses);
    }
    const sev = list(q['severity'], SEVERITIES);
    if (sev.length) {
      where.push(`m.severity IN (${sev.map(() => '?').join(',')})`);
      params.push(...sev);
    }
    const text = str(q['q'], 200);
    if (text) {
      where.push("(m.subject LIKE ? ESCAPE '\\' OR m.from_addr LIKE ? ESCAPE '\\' OR m.from_name LIKE ? ESCAPE '\\' OR m.message_id LIKE ? ESCAPE '\\' OR e.original_name LIKE ? ESCAPE '\\' OR m.sha256 = ?)");
      params.push(like(text), like(text), like(text), like(text), like(text), text.toLowerCase());
    }
    if (q['cluster']) {
      where.push('m.cluster_id = ?');
      params.push(q['cluster']);
    }
    if (q['indicator']) {
      where.push('m.id IN (SELECT message_id FROM observations WHERE indicator_id = ? AND case_id = ?)');
      params.push(int(q['indicator'], 0, 0, Number.MAX_SAFE_INTEGER), id);
    }
    if (q['finding']) {
      where.push("m.id IN (SELECT message_id FROM findings WHERE case_id = ? AND finding_id LIKE ? ESCAPE '\\')");
      params.push(id, (q['finding'] as string).replace(/[\\%_]/g, (c) => '\\' + c) + '%');
    }
    if (q['batch']) {
      where.push('e.batch_id = ?');
      params.push(q['batch']);
    }
    if (q['evidence']) {
      where.push('m.evidence_id = ?');
      params.push(q['evidence']);
    }
    if (q['intel'] === '1') where.push('m.intel_hits > 0');
    const sortCol = SORTS[q['sort'] ?? 'class'] ?? SORTS['class'];
    const dir = q['order'] === 'asc' ? 'ASC' : 'DESC';
    const pageSize = int(q['pageSize'], 100, 1, 500);
    const page = int(q['page'], 0, 0, 100_000);
    const from = `FROM messages m JOIN evidence e ON e.id = m.evidence_id LEFT JOIN clusters c ON c.id = m.cluster_id WHERE ${where.join(' AND ')}`;
    const total = ctx.db.get<{ n: number }>(`SELECT COUNT(*) AS n ${from}`, ...params)?.n ?? 0;
    const rows = ctx.db.all<MessageRow & { original_name: string; cluster_label: string | null }>(
      `SELECT m.*, e.original_name, c.label AS cluster_label ${from} ORDER BY ${sortCol} ${dir}, m.score DESC, m.id LIMIT ? OFFSET ?`,
      ...params,
      pageSize,
      page * pageSize,
    );
    const facets = ctx.db.all<{ class: string | null; status: string; n: number }>('SELECT class, status, COUNT(*) AS n FROM messages WHERE case_id = ? GROUP BY class, status', id);
    return { total, page, pageSize, items: rows.map(messageSummary), facets };
  });

  app.get('/api/cases/:id/messages/:mid', async (req) => {
    const { id, mid } = req.params as { id: string; mid: string };
    requireCase(ctx, req, id);
    return messageDetail(ctx, id, mid);
  });

  app.get('/api/cases/:id/messages/:mid/raw', async (req) => {
    const { id, mid } = req.params as { id: string; mid: string };
    requireCase(ctx, req, id);
    const m = ctx.db.get<MessageRow>('SELECT * FROM messages WHERE id = ? AND case_id = ?', mid, id);
    if (!m) throw notFound('Message not found.');
    const bytes = await ctx.store.read(m.blob_store, m.sha256, true);
    const max = ctx.cfg.limits.rawViewBytes;
    const view = bytes.subarray(0, max);
    const text = view.toString('latin1');
    // Header line offsets (for highlighting the exact evidence of a finding).
    const headers: { name: string; start: number; end: number }[] = [];
    const sep = /\r?\n\r?\n/.exec(text);
    const headerEnd = sep ? sep.index : text.length;
    let pos = 0;
    while (pos < headerEnd) {
      let end = text.indexOf('\n', pos);
      if (end < 0 || end > headerEnd) end = headerEnd;
      const line = text.slice(pos, end);
      if (/^[ \t]/.test(line) && headers.length) (headers[headers.length - 1] as { end: number }).end = end;
      else {
        const c = line.indexOf(':');
        if (c > 0) headers.push({ name: line.slice(0, c), start: pos, end });
      }
      pos = end + 1;
    }
    audit(ctx, req, 'message.raw-viewed', { caseId: id, target: mid, details: { sha256: m.sha256 } });
    return { size: bytes.length, truncated: bytes.length > max, encoding: 'latin1 (one character per byte)', text, headerEnd, headers, sha256: m.sha256, derivation: m.derivation };
  });

  app.post('/api/cases/:id/messages/:mid/reanalyze', async (req) => {
    const { id, mid } = req.params as { id: string; mid: string };
    requireCase(ctx, req, id, 'investigator');
    const m = ctx.db.get<MessageRow>('SELECT * FROM messages WHERE id = ? AND case_id = ?', mid, id);
    if (!m) throw notFound('Message not found.');
    if (m.status === 'duplicate') throw badRequest('This message is a duplicate; re-analyse the original instead.');
    ctx.db.run("UPDATE messages SET status = 'queued', error_code = NULL, error_detail = NULL WHERE id = ?", mid);
    ctx.queue.enqueue('analyze', id, mid, { priority: 2 });
    ctx.db.run('INSERT INTO events (case_id, subject_type, subject_id, ts, kind, detail) VALUES (?, ?, ?, ?, ?, ?)', id, 'message', mid, Date.now(), 'reanalysis-requested', JSON.stringify({ by: req.session?.user.username }));
    audit(ctx, req, 'message.reanalysis-requested', { caseId: id, target: mid });
    ctx.processor.kick();
    return { ok: true };
  });

  app.get('/api/cases/:id/progress', async (req) => {
    const { id } = req.params as { id: string };
    requireCase(ctx, req, id);
    const msgs = ctx.db.all<{ status: string; n: number }>('SELECT status, COUNT(*) AS n FROM messages WHERE case_id = ? GROUP BY status', id);
    const ev = ctx.db.all<{ status: string; n: number }>('SELECT status, COUNT(*) AS n FROM evidence WHERE case_id = ? GROUP BY status', id);
    const jobs = ctx.db.all<{ kind: string; status: string; n: number }>("SELECT kind, status, COUNT(*) AS n FROM jobs WHERE case_id = ? AND status IN ('queued', 'running') GROUP BY kind, status", id);
    const c = ctx.db.get<{ correlated_at: number | null; correlation_version: number }>('SELECT correlated_at, correlation_version FROM cases WHERE id = ?', id);
    const m = Object.fromEntries(msgs.map((x) => [x.status, x.n]));
    const e = Object.fromEntries(ev.map((x) => [x.status, x.n]));
    const pendingWork = jobs.reduce((s, j) => s + j.n, 0);
    return {
      messages: { queued: m['queued'] ?? 0, running: m['running'] ?? 0, analyzed: m['analyzed'] ?? 0, failed: m['failed'] ?? 0, duplicate: m['duplicate'] ?? 0, total: msgs.reduce((s, x) => s + x.n, 0) },
      evidence: e,
      jobs,
      correlation: { correlatedAt: c?.correlated_at ?? null, version: c?.correlation_version ?? 0, pending: jobs.some((j) => j.kind === 'correlate') },
      done: pendingWork === 0,
    };
  });

  app.get('/api/cases/:id/messages/:mid/history', async (req) => {
    const { id, mid } = req.params as { id: string; mid: string };
    requireCase(ctx, req, id);
    return ctx.db.all("SELECT ts, kind, detail FROM events WHERE subject_type = 'message' AND subject_id = ? AND case_id = ? ORDER BY ts", mid, id);
  });

  // ── Indicators ──
  app.get('/api/cases/:id/indicators', async (req) => {
    const { id } = req.params as { id: string };
    requireCase(ctx, req, id);
    const q = req.query as Record<string, string | undefined>;
    const where = ['o.case_id = ?'];
    const params: (string | number)[] = [id];
    const types = list(q['type']);
    if (types.length) {
      where.push(`i.type IN (${types.map(() => '?').join(',')})`);
      params.push(...types);
    }
    const roles = list(q['role']);
    if (roles.length) {
      where.push(`o.role IN (${roles.map(() => '?').join(',')})`);
      params.push(...roles);
    }
    const text = str(q['q'], 300);
    if (text) {
      where.push("i.value LIKE ? ESCAPE '\\'");
      params.push(like(text.toLowerCase()));
    }
    // Aliases avoid the names of message columns: in HAVING/ORDER BY SQLite would otherwise resolve
    // "intel_hits" to messages.intel_hits instead of the per-indicator count.
    const sort = q['sort'] === 'value' ? 'i.value ASC' : q['sort'] === 'intel' ? 'ind_intel DESC, ind_messages DESC' : 'ind_messages DESC, ind_intel DESC';
    const pageSize = int(q['pageSize'], 200, 1, 1000);
    const page = int(q['page'], 0, 0, 100_000);
    const intelOnly = q['intel'] === '1';
    const intelCount = '(SELECT COUNT(*) FROM intel_matches im WHERE im.case_id = ? AND im.indicator_id = i.id AND im.strength > 0)';
    const rows = ctx.db.all<{ id: number; type: string; value: string; ind_messages: number; roles: string; suspicious: number; ind_intel: number; intel_sources: string | null; first_seen: number | null; last_seen: number | null }>(
      `SELECT i.id, i.type, i.value, COUNT(DISTINCT o.message_id) AS ind_messages, GROUP_CONCAT(DISTINCT o.role) AS roles, MAX(o.suspicious) AS suspicious,
              ${intelCount} AS ind_intel,
              (SELECT GROUP_CONCAT(DISTINCT im.source) FROM intel_matches im WHERE im.case_id = ? AND im.indicator_id = i.id AND im.strength > 0) AS intel_sources,
              MIN(m.sent_at) AS first_seen, MAX(m.sent_at) AS last_seen
       FROM observations o JOIN indicators i ON i.id = o.indicator_id JOIN messages m ON m.id = o.message_id
       WHERE ${where.join(' AND ')} GROUP BY i.id ${intelOnly ? 'HAVING ind_intel > 0' : ''} ORDER BY ${sort} LIMIT ? OFFSET ?`,
      id,
      id,
      ...params,
      pageSize,
      page * pageSize,
    );
    const total = intelOnly
      ? ctx.db.get<{ n: number }>(`SELECT COUNT(*) AS n FROM (SELECT i.id, ${intelCount} AS ind_intel FROM observations o JOIN indicators i ON i.id = o.indicator_id WHERE ${where.join(' AND ')} GROUP BY i.id HAVING ind_intel > 0)`, id, ...params)?.n ?? 0
      : ctx.db.get<{ n: number }>(`SELECT COUNT(DISTINCT i.id) AS n FROM observations o JOIN indicators i ON i.id = o.indicator_id WHERE ${where.join(' AND ')}`, ...params)?.n ?? 0;
    const typeCounts = ctx.db.all<{ type: string; n: number }>('SELECT i.type, COUNT(DISTINCT i.id) AS n FROM observations o JOIN indicators i ON i.id = o.indicator_id WHERE o.case_id = ? GROUP BY i.type', id);
    return {
      total,
      page,
      pageSize,
      types: typeCounts,
      items: rows.map((r) => ({ id: r.id, type: r.type, value: r.value, messages: r.ind_messages, roles: r.roles.split(','), suspicious: !!r.suspicious, intelHits: r.ind_intel, intelSources: r.intel_sources ? r.intel_sources.split(',') : [], firstSeen: r.first_seen, lastSeen: r.last_seen })),
    };
  });

  app.get('/api/cases/:id/indicators/:iid', async (req) => {
    const { id, iid } = req.params as { id: string; iid: string };
    const { user } = requireCase(ctx, req, id);
    const ind = ctx.db.get<{ id: number; type: string; value: string }>('SELECT * FROM indicators WHERE id = ?', int(iid, -1, -1, Number.MAX_SAFE_INTEGER));
    if (!ind) throw notFound('Indicator not found.');
    const obs = ctx.db.all<MessageRow & { role: string; ref: string; context: string | null; suspicious: number }>(
      'SELECT m.*, o.role, o.ref, o.context, o.suspicious FROM observations o JOIN messages m ON m.id = o.message_id WHERE o.case_id = ? AND o.indicator_id = ? ORDER BY m.sent_at',
      id,
      ind.id,
    );
    if (!obs.length) throw notFound('Indicator not observed in this case.');
    const matches = ctx.db.all<{ source: string; match_type: string; matched_value: string; record_json: string; strength: number; matched_at: number; message_id: string }>(
      'SELECT source, match_type, matched_value, record_json, strength, matched_at, message_id FROM intel_matches WHERE case_id = ? AND indicator_id = ?',
      id,
      ind.id,
    );
    // Same value in other investigations the user may access (lab memory, never cross-case leakage).
    const others = ctx.db
      .all<{ case_id: string; name: string; n: number }>(
        'SELECT o.case_id, c.name, COUNT(DISTINCT o.message_id) AS n FROM observations o JOIN cases c ON c.id = o.case_id WHERE o.indicator_id = ? AND o.case_id != ? GROUP BY o.case_id',
        ind.id,
        id,
      )
      .filter((o) => caseRole(ctx.db, user, o.case_id) !== null)
      .map((o) => ({ caseId: o.case_id, caseName: o.name, messages: o.n }));
    const store = ctx.intel.store;
    const type = ind.type;
    const live =
      type === 'url'
        ? store.lookupUrl(ind.value)
        : type === 'hostname' || type === 'domain'
          ? store.lookupHost(ind.value)
          : type === 'ipv4' || type === 'ipv6'
            ? store.lookupIp(ind.value)
            : ['md5', 'sha1', 'sha256', 'email', 'phone', 'btc'].includes(type)
              ? store.lookupExact(type as 'md5', ind.value)
              : [];
    const intelType = intelTypeOf(type);
    const events = intelType ? store.lookupEvents(intelType, ind.value).slice(0, 30) : [];
    const lookups = intelType ? store.db.all('SELECT source, fetched_at AS fetchedAt, status, result_json FROM lookups WHERE type = ? AND value = ?', intelType, ind.value) : [];
    const host = type === 'url' ? (() => { try { return new URL(ind.value).hostname; } catch { return null; } })() : type === 'hostname' || type === 'domain' ? ind.value : null;
    const asn = type === 'ipv4' || type === 'ipv6' ? store.asn(ind.value) : null;
    return {
      indicator: { id: ind.id, type: ind.type, value: ind.value, registrable: host ? registrable(host) : null, popularityRank: host ? store.popularity(registrable(host)) : null, asn },
      observations: obs.map((o) => ({ message: messageSummary(o), role: o.role, ref: o.ref, context: o.context, suspicious: !!o.suspicious })),
      caseMatches: matches.map((x) => ({ source: x.source, matchType: x.match_type, matchedValue: x.matched_value, strength: x.strength, matchedAt: x.matched_at, messageId: x.message_id, record: JSON.parse(x.record_json) as unknown })),
      currentListings: live,
      events,
      onlineLookups: (lookups as { source: string; fetchedAt: number; status: string; result_json: string }[]).map((l) => ({ source: l.source, fetchedAt: l.fetchedAt, status: l.status, result: JSON.parse(l.result_json) as unknown })),
      otherCases: others,
    };
  });

  app.post('/api/cases/:id/lookups', { config: { rateLimit: { max: 60, timeWindow: '1 minute' } } }, async (req) => {
    const { id } = req.params as { id: string };
    requireCase(ctx, req, id, 'investigator');
    const c = ctx.db.get<{ online_lookups: number }>('SELECT online_lookups FROM cases WHERE id = ?', id);
    if (!ctx.cfg.allowOnlineLookups) throw new ApiError(403, 'online-disabled', 'Online lookups are disabled on this server.');
    if (!c?.online_lookups) throw new ApiError(403, 'online-not-enabled', 'Online lookups are off for this case. A case lead can enable them in case settings; they disclose the looked-up indicator to the selected third-party services.');
    const b = (req.body ?? {}) as Record<string, unknown>;
    const ind = ctx.db.get<{ id: number; type: string; value: string }>('SELECT i.* FROM indicators i JOIN observations o ON o.indicator_id = i.id WHERE i.id = ? AND o.case_id = ? LIMIT 1', int(b['indicatorId'], -1, -1, Number.MAX_SAFE_INTEGER), id);
    if (!ind) throw notFound('Indicator not found in this case.');
    const intelType = intelTypeOf(ind.type);
    if (!intelType) throw badRequest(`No online source supports ${ind.type} indicators.`);
    const only = list(b['sources']);
    const results = await ctx.intel.lookup(intelType, ind.value, only.length ? only : undefined);
    audit(ctx, req, 'intel.online-lookup', { caseId: id, target: String(ind.id), details: { type: ind.type, value: ind.value, sources: results.map((r) => ({ source: r.source, status: r.status, cached: r.cached })) } });
    if (results.some((r) => r.status === 'found' && !r.cached)) ctx.processor.scheduleCorrelation(id);
    return { indicator: ind, results };
  });

  // ── Search ──
  app.get('/api/cases/:id/search', async (req) => {
    const { id } = req.params as { id: string };
    requireCase(ctx, req, id);
    const text = str((req.query as Record<string, string>)['q'], 200);
    if (!text) return { messages: [], indicators: [], clusters: [] };
    const messages = ctx.db
      .all<MessageRow>("SELECT * FROM messages WHERE case_id = ? AND (subject LIKE ? ESCAPE '\\' OR from_addr LIKE ? ESCAPE '\\' OR message_id LIKE ? ESCAPE '\\' OR sha256 = ?) ORDER BY score DESC LIMIT 20", id, like(text), like(text), like(text), text.toLowerCase())
      .map(messageSummary);
    const indicators = ctx.db.all("SELECT DISTINCT i.id, i.type, i.value FROM indicators i JOIN observations o ON o.indicator_id = i.id WHERE o.case_id = ? AND i.value LIKE ? ESCAPE '\\' LIMIT 30", id, like(text.toLowerCase()));
    const clusters = ctx.db.all("SELECT id, label, size, verdict FROM clusters WHERE case_id = ? AND (label LIKE ? ESCAPE '\\' OR id LIKE ? ESCAPE '\\') LIMIT 10", id, like(text), like(text));
    return { messages, indicators, clusters };
  });

  void requireUser;
}

export function intelTypeOf(type: string): IntelType | null {
  if (type === 'url') return 'url';
  if (type === 'hostname' || type === 'domain') return 'domain';
  if (type === 'ipv4' || type === 'ipv6') return 'ip';
  if (type === 'md5' || type === 'sha1' || type === 'sha256' || type === 'email' || type === 'phone' || type === 'btc') return type;
  return null;
}
