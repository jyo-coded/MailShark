// Campaigns, graph, reports, intelligence sources, activity and administration.
import { createHash, randomUUID } from 'node:crypto';
import type { FastifyInstance } from 'fastify';
import type { AppContext } from '../context';
import { ApiError, attachmentHeader, audit, badRequest, int, list, notFound, requireAdmin, requireCase, requireUser, str } from './util';
import { buildGraph, DEFAULT_KINDS, NODE_KINDS, type NodeKind } from '../graph/build';
import { buildReport, REPORT_SCHEMA_VERSION, type ReportScope } from '../reports/model';
import { renderMarkdown } from '../reports/markdown';
import { renderDocx } from '../reports/docx';
import { REPORT_JSON_SCHEMA } from '../reports/schema';
import { messageSummary, type MessageRow } from './messages';

const FORMATS = { json: { ext: 'json', type: 'application/json; charset=utf-8' }, md: { ext: 'md', type: 'text/markdown; charset=utf-8' }, docx: { ext: 'docx', type: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document' } } as const;

export function registerInsight(app: FastifyInstance, ctx: AppContext): void {
  // ── Campaigns ──
  app.get('/api/cases/:id/clusters', async (req) => {
    const { id } = req.params as { id: string };
    requireCase(ctx, req, id);
    return ctx.db
      .all<{ id: string; label: string; size: number; confidence: string; cohesion: number; first_seen: number | null; last_seen: number | null; verdict: string; profile_json: string; external_json: string }>('SELECT * FROM clusters WHERE case_id = ? ORDER BY size DESC', id)
      .map((c) => {
        const p = JSON.parse(c.profile_json) as { density: number; exactEdges: number; profile: { invariants: { label: string }[]; rotated: { label: string }[] }; sharedIndicators: unknown[] };
        return { id: c.id, label: c.label, size: c.size, confidence: c.confidence, cohesion: c.cohesion, density: p.density, exactEdges: p.exactEdges, firstSeen: c.first_seen, lastSeen: c.last_seen, verdict: c.verdict, invariants: p.profile.invariants.map((i) => i.label), rotated: p.profile.rotated.map((i) => i.label), sharedIndicators: p.sharedIndicators.slice(0, 5), external: JSON.parse(c.external_json) as unknown[] };
      });
  });

  app.get('/api/cases/:id/clusters/:cid', async (req) => {
    const { id, cid } = req.params as { id: string; cid: string };
    requireCase(ctx, req, id);
    const c = ctx.db.get<{ id: string; label: string; size: number; confidence: string; cohesion: number; first_seen: number | null; last_seen: number | null; verdict: string; profile_json: string; external_json: string; method: string }>('SELECT * FROM clusters WHERE id = ? AND case_id = ?', cid, id);
    if (!c) throw notFound('Cluster not found.');
    const p = JSON.parse(c.profile_json) as { members: { id: string; strength: number }[]; density: number; exactEdges: number; profile: unknown; sharedIndicators: unknown[] };
    const memberIds = new Set(p.members.map((m) => m.id));
    const messages = p.members.map((m) => {
      const row = ctx.db.get<MessageRow>('SELECT * FROM messages WHERE id = ?', m.id);
      return row ? { ...messageSummary(row), membership: m.strength } : { id: m.id, membership: m.strength };
    });
    const relationships = ctx.db
      .all<{ a: string; b: string; tier: string; score: number; evidence_json: string }>('SELECT a, b, tier, score, evidence_json FROM edges WHERE case_id = ? ORDER BY score DESC', id)
      .filter((e) => memberIds.has(e.a) && memberIds.has(e.b))
      .map((e) => ({ a: e.a, b: e.b, tier: e.tier, score: e.score, evidence: JSON.parse(e.evidence_json) as unknown }));
    return { id: c.id, label: c.label, size: c.size, confidence: c.confidence, cohesion: c.cohesion, density: p.density, exactEdges: p.exactEdges, firstSeen: c.first_seen, lastSeen: c.last_seen, verdict: c.verdict, method: c.method, profile: p.profile, sharedIndicators: p.sharedIndicators, external: JSON.parse(c.external_json) as unknown, messages, relationships };
  });

  app.get('/api/cases/:id/external-campaigns', async (req) => {
    const { id } = req.params as { id: string };
    requireCase(ctx, req, id);
    return ctx.db
      .all<{ source: string; event_id: string; name: string; assessment: string; confidence: string; message_count: number; detail_json: string }>(
        "SELECT * FROM external_campaigns WHERE case_id = ? ORDER BY CASE assessment WHEN 'reported-association' THEN 0 ELSE 1 END, message_count DESC",
        id,
      )
      .map((x) => ({ ...(JSON.parse(x.detail_json) as Record<string, unknown>), source: x.source, eventId: x.event_id, name: x.name, assessment: x.assessment, confidence: x.confidence, messageCount: x.message_count }));
  });

  app.get('/api/intel/events/:source/:eventId', async (req) => {
    requireUser(req);
    const { source, eventId } = req.params as { source: string; eventId: string };
    const e = ctx.intel.store.event(source, eventId);
    if (!e) throw notFound('Event not found in the intelligence store.');
    return e;
  });

  // ── Graph ──
  app.get('/api/cases/:id/graph', async (req) => {
    const { id } = req.params as { id: string };
    requireCase(ctx, req, id);
    const q = req.query as Record<string, string | undefined>;
    const kinds = list(q['types'], NODE_KINDS) as NodeKind[];
    const classes = list(q['classes']);
    const sources = list(q['sources']);
    const focus = list(q['focus']).filter((f) => /^[mcxi]:[\w:.-]+$/.test(f)).slice(0, 20);
    return buildGraph(ctx.db, id, {
      kinds: new Set(kinds.length ? kinds : DEFAULT_KINDS),
      classes: classes.length ? new Set(classes) : null,
      from: q['from'] ? int(q['from'], 0, 0, Number.MAX_SAFE_INTEGER) : null,
      to: q['to'] ? int(q['to'], 0, 0, Number.MAX_SAFE_INTEGER) : null,
      minEdge: Math.min(1, Math.max(0, Number(q['minEdge'] ?? 0.6) || 0.6)),
      sources: sources.length ? new Set(sources) : null,
      q: str(q['q'], 200),
      focus,
      depth: int(q['depth'], 1, 1, 3),
      limit: int(q['limit'], 600, 20, 3000),
      similarity: q['similarity'] !== '0',
      minDegree: int(q['minDegree'], 1, 1, 50),
      cluster: str(q['cluster'], 120),
    });
  });

  // ── Reports ──
  app.get('/api/schema/report', async () => REPORT_JSON_SCHEMA);

  app.post('/api/cases/:id/reports', { config: { rateLimit: { max: 30, timeWindow: '1 minute' } } }, async (req, reply) => {
    const { id } = req.params as { id: string };
    const { user } = requireCase(ctx, req, id);
    const b = (req.body ?? {}) as Record<string, unknown>;
    const format = (str(b['format'], 10) ?? 'json') as keyof typeof FORMATS;
    if (!FORMATS[format]) throw badRequest('Format must be json, md or docx.');
    let scope: ReportScope = { kind: 'case' };
    if (b['scope'] === 'batch') {
      const batchId = str(b['batchId'], 60);
      if (!batchId || !ctx.db.get('SELECT 1 FROM batches WHERE id = ? AND case_id = ?', batchId, id)) throw badRequest('Unknown batch.');
      scope = { kind: 'batch', batchId };
    } else if (b['scope'] === 'messages') {
      const ids = list(b['messageIds']).slice(0, 5000);
      if (!ids.length) throw badRequest('Select at least one message.');
      scope = { kind: 'messages', ids };
    }
    const full = ctx.auth.user(user.id) as NonNullable<ReturnType<typeof ctx.auth.user>>;
    const report = buildReport(ctx, id, scope, full);
    let bytes: Buffer;
    if (format === 'json') bytes = Buffer.from(JSON.stringify(report, null, 2));
    else if (format === 'md') bytes = Buffer.from(renderMarkdown(report));
    else bytes = await renderDocx(report);
    const fileSha = createHash('sha256').update(bytes).digest('hex');
    await ctx.store.putBytes('reports', bytes);
    const rid = `rep_${randomUUID()}`;
    ctx.db.run(
      'INSERT INTO reports (id, case_id, created_by, created_at, scope, scope_ref, format, file_sha256, data_sha256, size, report_uuid, schema_version) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
      rid,
      id,
      user.id,
      Date.now(),
      scope.kind,
      scope.kind === 'batch' ? scope.batchId : scope.kind === 'messages' ? scope.ids.length + ' messages' : null,
      format,
      fileSha,
      report.integrity.dataSha256,
      bytes.length,
      report.report.id,
      REPORT_SCHEMA_VERSION,
    );
    audit(ctx, req, 'report.generated', { caseId: id, target: rid, details: { format, scope: scope.kind, fileSha256: fileSha, dataSha256: report.integrity.dataSha256, reportId: report.report.id } });
    return reply.code(201).send({ id: rid, format, size: bytes.length, fileSha256: fileSha, dataSha256: report.integrity.dataSha256, reportId: report.report.id });
  });

  app.get('/api/cases/:id/reports', async (req) => {
    const { id } = req.params as { id: string };
    requireCase(ctx, req, id);
    return ctx.db.all(
      'SELECT r.id, r.created_at AS createdAt, u.username AS createdBy, r.scope, r.scope_ref AS scopeRef, r.format, r.file_sha256 AS fileSha256, r.data_sha256 AS dataSha256, r.size, r.report_uuid AS reportId, r.schema_version AS schemaVersion FROM reports r JOIN users u ON u.id = r.created_by WHERE r.case_id = ? ORDER BY r.created_at DESC',
      id,
    );
  });

  app.get('/api/cases/:id/reports/:rid/download', async (req, reply) => {
    const { id, rid } = req.params as { id: string; rid: string };
    requireCase(ctx, req, id);
    const r = ctx.db.get<{ file_sha256: string; format: keyof typeof FORMATS; created_at: number; report_uuid: string }>('SELECT file_sha256, format, created_at, report_uuid FROM reports WHERE id = ? AND case_id = ?', rid, id);
    if (!r) throw notFound('Report not found.');
    const bytes = await ctx.store.read('reports', r.file_sha256, true);
    const c = ctx.db.get<{ name: string }>('SELECT name FROM cases WHERE id = ?', id);
    audit(ctx, req, 'report.downloaded', { caseId: id, target: rid, details: { fileSha256: r.file_sha256 } });
    const name = `${(c?.name ?? 'case').replace(/[^\w.-]+/g, '_').slice(0, 60)}_report_${new Date(r.created_at).toISOString().slice(0, 10)}_${r.report_uuid.slice(0, 8)}.${FORMATS[r.format].ext}`;
    return reply.header('content-type', FORMATS[r.format].type).header('content-disposition', attachmentHeader(name)).header('x-report-sha256', r.file_sha256).header('cache-control', 'no-store').send(bytes);
  });

  // ── Intelligence sources ──
  app.get('/api/intel/sources', async (req) => {
    requireUser(req);
    return { sources: ctx.intel.sources(), snapshot: ctx.intel.store.snapshotId(), autoSync: ctx.cfg.intel.autoSync, onlineLookupsAllowed: ctx.cfg.allowOnlineLookups };
  });

  app.get('/api/intel/sources/:sid/history', async (req) => {
    requireUser(req);
    const { sid } = req.params as { sid: string };
    return ctx.intel.store.recentSyncs(sid, 20);
  });

  app.post('/api/intel/sources/:sid/sync', async (req) => {
    requireAdmin(req);
    const { sid } = req.params as { sid: string };
    const s = ctx.intel.sources().find((x) => x.id === sid);
    if (!s) throw notFound('Unknown source.');
    if (s.kind === 'lookup') throw badRequest('Lookup services are queried per indicator, not synchronised.');
    if (s.missing.length) throw new ApiError(409, 'not-configured', `Set ${s.missing.join(', ')} to enable this source.`);
    audit(ctx, req, 'intel.sync-requested', { target: sid });
    void ctx.intel.enqueue([sid]);
    return { queued: true };
  });

  app.patch('/api/intel/sources/:sid', async (req) => {
    requireAdmin(req);
    const { sid } = req.params as { sid: string };
    const b = (req.body ?? {}) as Record<string, unknown>;
    if (typeof b['enabled'] !== 'boolean') throw badRequest('enabled must be true or false.');
    try {
      ctx.intel.setEnabled(sid, b['enabled']);
    } catch {
      throw notFound('Unknown source.');
    }
    audit(ctx, req, 'intel.source-updated', { target: sid, details: { enabled: b['enabled'] } });
    return { ok: true };
  });

  // ── Activity & administration ──
  app.get('/api/cases/:id/activity', async (req) => {
    const { id } = req.params as { id: string };
    requireCase(ctx, req, id);
    const q = req.query as Record<string, string | undefined>;
    const limit = int(q['limit'], 200, 1, 1000);
    const auditRows = ctx.audit.list({ caseId: id, limit }).map((a) => ({ type: 'audit', seq: a.seq, ts: a.ts, user: a.username, action: a.action, target: a.target, details: a.details ? (JSON.parse(a.details) as unknown) : null }));
    const events = ctx.db.all<{ ts: number; subject_type: string; subject_id: string; kind: string; detail: string | null }>('SELECT ts, subject_type, subject_id, kind, detail FROM events WHERE case_id = ? ORDER BY ts DESC LIMIT ?', id, limit).map((e) => ({ type: 'processing', ts: e.ts, subjectType: e.subject_type, subjectId: e.subject_id, kind: e.kind, detail: e.detail ? (JSON.parse(e.detail) as unknown) : null }));
    return { audit: auditRows, processing: events };
  });

  app.get('/api/admin/audit', async (req) => {
    requireAdmin(req);
    const q = req.query as Record<string, string | undefined>;
    return ctx.audit.list({ limit: int(q['limit'], 200, 1, 1000), before: q['before'] ? int(q['before'], 0, 0, Number.MAX_SAFE_INTEGER) : null });
  });

  app.get('/api/admin/audit/verify', async (req) => {
    requireAdmin(req);
    const v = ctx.audit.verify();
    audit(ctx, req, 'audit.verified', { details: v });
    return v;
  });

  app.get('/api/admin/system', async (req) => {
    requireAdmin(req);
    const overdue = ctx.db.all('SELECT id, name, retention_until AS retentionUntil, legal_hold AS legalHold FROM cases WHERE retention_until IS NOT NULL AND retention_until < ? ORDER BY retention_until', Date.now());
    const failedJobs = ctx.db.all('SELECT id, kind, case_id AS caseId, ref, attempts, last_error AS lastError, updated_at AS updatedAt FROM jobs WHERE status = ? ORDER BY updated_at DESC LIMIT 50', 'failed');
    return { workers: ctx.pool.stats(), queue: ctx.queue.depth(), retentionOverdue: overdue, failedJobs, dataDir: ctx.cfg.dataDir, limits: ctx.cfg.limits, thresholds: ctx.cfg.thresholds };
  });
}
