// Evidence intake (multipart batches of up to 100 files), batch/evidence listings, verified downloads.
import { randomUUID } from 'node:crypto';
import { unlink } from 'node:fs/promises';
import type { FastifyInstance } from 'fastify';
import type { AppContext } from '../context';
import { detectFormat, FormatError } from '../evidence/formats';
import { ApiError, attachmentHeader, audit, cleanFileName, notFound, requireCase, str } from './util';

interface Staged {
  name: string;
  declaredType: string | null;
  size: number;
  sha256: string;
  sha1: string;
  md5: string;
  tmpPath: string;
  format: string | null;
  error: { code: string; message: string } | null;
}

export function registerEvidence(app: FastifyInstance, ctx: AppContext): void {
  app.post('/api/cases/:id/batches', { config: { rateLimit: { max: 120, timeWindow: '1 minute' } } }, async (req, reply) => {
    const { id: caseId } = req.params as { id: string };
    const { user } = requireCase(ctx, req, caseId, 'investigator');
    if (!req.isMultipart()) throw new ApiError(415, 'unsupported-media-type', 'Upload evidence as multipart/form-data.');
    const c = ctx.db.get<{ status: string }>('SELECT status FROM cases WHERE id = ?', caseId);
    if (c?.status !== 'open') throw new ApiError(409, 'case-not-open', 'Evidence can only be added to an open case.');
    const limits = ctx.cfg.limits;
    const staged: Staged[] = [];
    let note: string | null = null;
    let total = 0;
    const cleanup = async (): Promise<void> => {
      await Promise.all(staged.filter((s) => s.tmpPath).map((s) => unlink(s.tmpPath).catch(() => undefined)));
    };
    try {
      for await (const part of req.parts({ limits: { files: limits.filesPerBatch, fileSize: limits.fileBytes + 1, fields: 10, fieldSize: 4096, parts: limits.filesPerBatch + 10, headerPairs: 200 } })) {
        if (part.type === 'field') {
          if (part.fieldname === 'note') note = str(part.value, 2000);
          continue;
        }
        const name = cleanFileName(part.filename);
        const ing = await ctx.store.ingestStream(part.file, limits.fileBytes);
        if (ing.truncated || part.file.truncated) {
          if (ing.tmpPath) await unlink(ing.tmpPath).catch(() => undefined);
          staged.push({ name, declaredType: part.mimetype ?? null, size: ing.size, sha256: '', sha1: '', md5: '', tmpPath: '', format: null, error: { code: 'file-too-large', message: `Larger than the ${Math.round(limits.fileBytes / 1048576)} MB per-file limit (MAILSHARK_MAX_FILE_MB).` } });
          continue;
        }
        total += ing.size;
        if (total > limits.batchBytes) throw new ApiError(413, 'batch-too-large', `The batch exceeds ${Math.round(limits.batchBytes / 1048576)} MB (MAILSHARK_MAX_BATCH_MB). Split it into smaller batches.`);
        let format: string | null = null;
        let error: Staged['error'] = null;
        try {
          format = detectFormat(ing.head).format;
        } catch (e) {
          error = e instanceof FormatError ? { code: e.code, message: e.message } : { code: 'unsupported-format', message: 'Unrecognised content.' };
        }
        staged.push({ name, declaredType: part.mimetype ?? null, size: ing.size, sha256: ing.sha256, sha1: ing.sha1, md5: ing.md5, tmpPath: ing.tmpPath, format, error });
      }
    } catch (e) {
      await cleanup();
      const code = (e as { code?: string }).code;
      if (code === 'FST_FILES_LIMIT') throw new ApiError(413, 'too-many-files', `A batch can contain at most ${limits.filesPerBatch} files. Nothing from this batch was stored.`);
      if (code === 'FST_PARTS_LIMIT' || code === 'FST_FIELDS_LIMIT') throw new ApiError(413, 'too-many-parts', 'The upload has too many form parts.');
      throw e;
    }
    if (!staged.length) throw new ApiError(400, 'no-files', 'No files were uploaded.');

    const batchId = `batch_${randomUUID()}`;
    const now = Date.now();
    const results: Record<string, unknown>[] = [];
    // Commit the bytes first (content-addressed, idempotent), then the records in one transaction.
    for (const s of staged) {
      if (s.tmpPath) {
        await ctx.store.commit('evidence', s.tmpPath, s.sha256);
        s.tmpPath = '';
      }
    }
    const toExpand: string[] = [];
    ctx.db.tx(() => {
      ctx.db.run('INSERT INTO batches (id, case_id, created_by, created_at, file_count, accepted_count, total_bytes, note) VALUES (?, ?, ?, ?, ?, ?, ?, ?)', batchId, caseId, user.id, now, staged.length, staged.filter((s) => !s.error).length, total, note);
      for (const s of staged) {
        const id = `ev_${randomUUID()}`;
        let status = 'stored';
        let duplicateOf: string | null = null;
        if (s.error) status = 'rejected';
        else {
          const dup = ctx.db.get<{ id: string }>("SELECT id FROM evidence WHERE case_id = ? AND sha256 = ? AND status != 'rejected' ORDER BY received_at LIMIT 1", caseId, s.sha256);
          if (dup) {
            status = 'duplicate';
            duplicateOf = dup.id;
          }
        }
        ctx.db.run(
          `INSERT INTO evidence (id, case_id, batch_id, original_name, declared_type, format, size, sha256, sha1, md5, received_at, uploaded_by, status, duplicate_of, error_code, error_detail)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          id,
          caseId,
          batchId,
          s.name,
          s.declaredType,
          s.format,
          s.size,
          s.sha256 || '-',
          s.sha1 || '-',
          s.md5 || '-',
          now,
          user.id,
          status,
          duplicateOf,
          s.error?.code ?? null,
          s.error?.message ?? null,
        );
        ctx.db.run('INSERT INTO events (case_id, subject_type, subject_id, ts, kind, detail) VALUES (?, ?, ?, ?, ?, ?)', caseId, 'evidence', id, now, status === 'stored' ? 'received' : status, JSON.stringify({ sha256: s.sha256 || null, size: s.size, name: s.name, error: s.error, duplicateOf }));
        if (status === 'stored') toExpand.push(id);
        results.push({ id, originalName: s.name, size: s.size, sha256: s.sha256 || null, format: s.format, status, duplicateOf, error: s.error });
      }
      for (const id of toExpand) ctx.queue.enqueue('expand', caseId, id, { priority: 3 });
      ctx.db.run('UPDATE cases SET updated_at = ? WHERE id = ?', now, caseId);
    });
    audit(ctx, req, 'evidence.uploaded', {
      caseId,
      target: batchId,
      details: { files: staged.length, accepted: toExpand.length, bytes: total, items: staged.map((s) => ({ name: s.name, sha256: s.sha256 || null, size: s.size, error: s.error?.code ?? null })) },
    });
    ctx.processor.kick();
    return reply.code(201).send({ batchId, accepted: toExpand.length, rejected: staged.filter((s) => s.error).length, duplicates: results.filter((r) => r['status'] === 'duplicate').length, evidence: results });
  });

  app.get('/api/cases/:id/batches', async (req) => {
    const { id } = req.params as { id: string };
    requireCase(ctx, req, id);
    return ctx.db.all(
      `SELECT b.id, b.created_at AS createdAt, b.file_count AS fileCount, b.accepted_count AS acceptedCount, b.total_bytes AS totalBytes, b.note, u.username AS createdBy,
        (SELECT COUNT(*) FROM messages m JOIN evidence e ON e.id = m.evidence_id WHERE e.batch_id = b.id) AS messages,
        (SELECT COUNT(*) FROM messages m JOIN evidence e ON e.id = m.evidence_id WHERE e.batch_id = b.id AND m.status IN ('queued', 'running')) AS pending,
        (SELECT COUNT(*) FROM messages m JOIN evidence e ON e.id = m.evidence_id WHERE e.batch_id = b.id AND m.status = 'failed') AS failed
       FROM batches b JOIN users u ON u.id = b.created_by WHERE b.case_id = ? ORDER BY b.created_at DESC`,
      id,
    );
  });

  app.get('/api/cases/:id/evidence', async (req) => {
    const { id } = req.params as { id: string };
    requireCase(ctx, req, id);
    const q = req.query as Record<string, string | undefined>;
    const batch = q['batch'] && /^batch_[a-f0-9-]{36}$/.test(q['batch']) ? q['batch'] : null;
    return ctx.db.all(
      `SELECT e.id, e.batch_id AS batchId, e.original_name AS originalName, e.declared_type AS declaredType, e.format, e.size, e.sha256, e.sha1, e.md5,
              e.received_at AS receivedAt, u.username AS uploadedBy, e.status, e.duplicate_of AS duplicateOf, e.message_count AS messageCount, e.truncated,
              e.error_code AS errorCode, e.error_detail AS errorDetail,
              (SELECT COUNT(*) FROM messages m WHERE m.evidence_id = e.id AND m.status = 'analyzed') AS analyzed,
              (SELECT COUNT(*) FROM messages m WHERE m.evidence_id = e.id AND m.status IN ('queued', 'running')) AS pending,
              (SELECT COUNT(*) FROM messages m WHERE m.evidence_id = e.id AND m.status = 'failed') AS failed
       FROM evidence e JOIN users u ON u.id = e.uploaded_by WHERE e.case_id = ? ${batch ? 'AND e.batch_id = ?' : ''} ORDER BY e.received_at DESC, e.original_name`,
      id,
      ...(batch ? [batch] : []),
    );
  });

  app.get('/api/cases/:id/evidence/:eid', async (req) => {
    const { id, eid } = req.params as { id: string; eid: string };
    requireCase(ctx, req, id);
    const e = ctx.db.get<Record<string, unknown>>('SELECT * FROM evidence WHERE id = ? AND case_id = ?', eid, id);
    if (!e) throw notFound('Evidence not found.');
    const messages = ctx.db.all('SELECT id, container_index AS containerIndex, byte_offset AS byteOffset, size, sha256, derivation, status, class, subject FROM messages WHERE evidence_id = ? ORDER BY container_index LIMIT 5000', eid);
    const history = ctx.db.all("SELECT ts, kind, detail FROM events WHERE subject_type = 'evidence' AND subject_id = ? ORDER BY ts", eid);
    return { evidence: e, messages, history };
  });

  app.post('/api/cases/:id/evidence/:eid/verify', async (req) => {
    const { id, eid } = req.params as { id: string; eid: string };
    requireCase(ctx, req, id);
    const e = ctx.db.get<{ sha256: string; size: number; status: string }>('SELECT sha256, size, status FROM evidence WHERE id = ? AND case_id = ?', eid, id);
    if (!e) throw notFound('Evidence not found.');
    if (e.status === 'rejected' && e.sha256 === '-') return { ok: false, reason: 'This file was rejected at intake and its bytes were not stored.' };
    const v = await ctx.store.verify('evidence', e.sha256);
    audit(ctx, req, 'evidence.verified', { caseId: id, target: eid, details: { ok: v.ok, expected: e.sha256, actual: v.actual } });
    return { ok: v.ok, expected: e.sha256, actual: v.actual, size: v.size, expectedSize: e.size, checkedAt: Date.now() };
  });

  app.get('/api/cases/:id/evidence/:eid/download', async (req, reply) => {
    const { id, eid } = req.params as { id: string; eid: string };
    requireCase(ctx, req, id);
    const e = ctx.db.get<{ sha256: string; original_name: string; status: string }>('SELECT sha256, original_name, status FROM evidence WHERE id = ? AND case_id = ?', eid, id);
    if (!e || e.sha256 === '-') throw notFound('Evidence not found.');
    const v = await ctx.store.verify('evidence', e.sha256);
    if (!v.ok) {
      audit(ctx, req, 'evidence.integrity-failure', { caseId: id, target: eid, details: { expected: e.sha256, actual: v.actual } });
      throw new ApiError(500, 'integrity-failure', 'The stored file no longer matches its recorded SHA-256. It has not been served. This incident is in the audit log.');
    }
    audit(ctx, req, 'evidence.downloaded', { caseId: id, target: eid, details: { sha256: e.sha256 } });
    return reply
      .header('content-type', 'application/octet-stream')
      .header('content-disposition', attachmentHeader(e.original_name))
      .header('x-evidence-sha256', e.sha256)
      .header('cache-control', 'no-store')
      .send(ctx.store.stream('evidence', e.sha256));
  });
}
