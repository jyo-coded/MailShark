// Processing pipeline: claims jobs, runs them in the worker pool, persists results atomically.
//   expand    evidence file → message artifacts (+ duplicate detection) → analyze jobs
//   analyze   message → engine report → results, findings, observations, classification
//   correlate case → edges, clusters, intel matches, external campaigns (debounced per case)
import { createHash } from 'node:crypto';
import { gzipSync } from 'node:zlib';
import type { Report } from '../../../engine/src/types';
import { analysisConfigFingerprint, type Config } from '../config';
import type { Db } from '../db/sqlite';
import type { JobQueue, Job } from '../jobs/queue';
import { TaskError, type WorkerPool } from '../jobs/pool';
import type { AnalyzeOutput, ExpandOutput } from '../jobs/worker';
import type { CorrelationResult } from '../correlation/engine';
import type { ExternalCampaign, ExternalMatch } from '../correlation/external';
import type { BlobKind } from '../evidence/store';

const sha256 = (s: string | Buffer): string => createHash('sha256').update(s).digest('hex');

export interface ProcessorDeps {
  cfg: Config;
  db: Db;
  queue: JobQueue;
  pool: WorkerPool;
  intelDbPath: string | null;
  caseDbPath: string;
  log: (level: 'info' | 'warn' | 'error', msg: string) => void;
}

export class Processor {
  private timer: NodeJS.Timeout | null = null;
  private ticking = false;
  private inflight = 0;
  private stopped = false;

  constructor(private readonly d: ProcessorDeps) {}

  start(): void {
    const r = this.d.queue.recover();
    if (r.requeued.length || r.failed.length) this.d.log('info', `[jobs] recovered after restart: ${r.requeued.length} re-queued, ${r.failed.length} failed`);
    // The interruption is part of the processing history of each affected item.
    for (const [jobs, kind] of [[r.requeued, 'resumed-after-interruption'], [r.failed, 'failed-after-interruption']] as const) {
      for (const j of jobs) {
        const subject = j.kind === 'expand' ? 'evidence' : j.kind === 'analyze' ? 'message' : 'case';
        if (j.case_id) this.event(j.case_id, subject, j.ref, kind, { attempt: j.attempts });
        if (j.kind === 'analyze' && kind === 'failed-after-interruption') this.d.db.run("UPDATE messages SET status = 'failed', class = 'failed', error_code = 'interrupted', error_detail = 'Analysis was interrupted repeatedly.' WHERE id = ?", j.ref);
        if (j.kind === 'expand' && kind === 'failed-after-interruption') this.d.db.run("UPDATE evidence SET status = 'failed', error_code = 'interrupted', error_detail = 'Expansion was interrupted repeatedly.' WHERE id = ?", j.ref);
      }
    }
    // Messages left "running" by a crash are reflected back to "queued" with their jobs.
    this.d.db.run("UPDATE messages SET status = 'queued' WHERE status = 'running'");
    this.timer = setInterval(() => this.kick(), 250);
    this.timer.unref();
  }

  async stop(): Promise<void> {
    this.stopped = true;
    if (this.timer) clearInterval(this.timer);
  }

  kick(): void {
    if (this.ticking || this.stopped) return;
    this.ticking = true;
    try {
      const free = this.d.pool.idle();
      if (free <= 0) return;
      const jobs = this.d.queue.claim(free, 15 * 60_000);
      for (const job of jobs) {
        this.inflight++;
        void this.run(job).finally(() => {
          this.inflight--;
          setImmediate(() => this.kick());
        });
      }
    } catch (e) {
      this.d.log('error', `[jobs] scheduler error: ${e instanceof Error ? e.message : String(e)}`);
    } finally {
      this.ticking = false;
    }
  }

  busy(): number {
    return this.inflight;
  }

  private event(caseId: string, subjectType: string, subjectId: string, kind: string, detail?: unknown): void {
    this.d.db.run('INSERT INTO events (case_id, subject_type, subject_id, ts, kind, detail) VALUES (?, ?, ?, ?, ?, ?)', caseId, subjectType, subjectId, Date.now(), kind, detail === undefined ? null : JSON.stringify(detail));
  }

  private async run(job: Job): Promise<void> {
    try {
      if (job.kind === 'expand') await this.expand(job);
      else if (job.kind === 'analyze') await this.analyze(job);
      else await this.correlate(job);
      this.d.queue.complete(job.id);
    } catch (e) {
      const te = e instanceof TaskError ? e : new TaskError('internal-error', e instanceof Error ? e.message : String(e), false);
      const outcome = this.d.queue.fail(job, `${te.code}: ${te.message}`, te.retryable);
      this.onFailure(job, te, outcome);
    }
  }

  private onFailure(job: Job, e: TaskError, outcome: 'retry' | 'failed'): void {
    const caseId = job.case_id ?? '';
    try {
      if (job.kind === 'expand') {
        if (outcome === 'failed') this.d.db.run("UPDATE evidence SET status = 'failed', error_code = ?, error_detail = ? WHERE id = ?", e.code, e.message.slice(0, 1000), job.ref);
        this.event(caseId, 'evidence', job.ref, outcome === 'retry' ? 'retry-scheduled' : 'expansion-failed', { code: e.code, message: e.message, attempt: job.attempts });
      } else if (job.kind === 'analyze') {
        this.d.db.run(
          outcome === 'retry' ? "UPDATE messages SET status = 'queued', error_code = ?, error_detail = ?, attempts = ? WHERE id = ?" : "UPDATE messages SET status = 'failed', class = 'failed', error_code = ?, error_detail = ?, attempts = ? WHERE id = ?",
          e.code,
          e.message.slice(0, 1000),
          job.attempts,
          job.ref,
        );
        this.event(caseId, 'message', job.ref, outcome === 'retry' ? 'retry-scheduled' : 'analysis-failed', { code: e.code, message: e.message, attempt: job.attempts });
      } else {
        this.event(caseId, 'case', caseId, outcome === 'retry' ? 'correlation-retry' : 'correlation-failed', { code: e.code, message: e.message });
      }
    } catch (err) {
      this.d.log('error', `[jobs] could not record failure of job ${job.id}: ${err instanceof Error ? err.message : String(err)}`);
    }
    this.d.log(outcome === 'retry' ? 'warn' : 'error', `[jobs] ${job.kind} ${job.ref} ${outcome === 'retry' ? 'will retry' : 'failed'}: ${e.code}: ${e.message}`);
  }

  // ── expand ──

  private async expand(job: Job): Promise<void> {
    const ev = this.d.db.get<{ id: string; case_id: string; sha256: string; status: string }>('SELECT id, case_id, sha256, status FROM evidence WHERE id = ?', job.ref);
    if (!ev) return; // case deleted meanwhile
    this.d.db.run("UPDATE evidence SET status = 'expanding' WHERE id = ?", ev.id);
    const out = await this.d.pool.run<ExpandOutput>({ kind: 'expand', dataDir: this.d.cfg.dataDir, evidenceSha256: ev.sha256, maxMessages: this.d.cfg.limits.messagesPerContainer }, this.d.cfg.expandTimeoutMs);
    const now = Date.now();
    const toAnalyze: string[] = [];
    this.d.db.tx(() => {
      if (!this.d.db.get('SELECT 1 FROM evidence WHERE id = ?', ev.id)) return;
      for (const m of out.messages) {
        const id = `msg_${sha256(`${ev.id}:${m.index}`).slice(0, 20)}`;
        if (this.d.db.get('SELECT 1 FROM messages WHERE id = ?', id)) continue;
        // The same message bytes already analysed in this case: link instead of re-analysing.
        const dup = this.d.db.get<{ id: string }>("SELECT id FROM messages WHERE case_id = ? AND sha256 = ? AND status != 'duplicate' ORDER BY created_at LIMIT 1", ev.case_id, m.sha256);
        this.d.db.run(
          `INSERT INTO messages (id, case_id, evidence_id, container_index, byte_offset, size, sha256, blob_store, derivation, status, duplicate_of, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          id,
          ev.case_id,
          ev.id,
          m.index,
          m.offset,
          m.size,
          m.sha256,
          m.blobStore,
          m.derivation,
          dup ? 'duplicate' : 'queued',
          dup?.id ?? null,
          now,
        );
        if (dup) this.event(ev.case_id, 'message', id, 'duplicate', { of: dup.id, sha256: m.sha256 });
        else {
          toAnalyze.push(id);
          this.event(ev.case_id, 'message', id, 'queued', { derivation: m.derivation, offset: m.offset, notes: m.notes });
        }
      }
      this.d.db.run(
        "UPDATE evidence SET status = 'expanded', format = ?, message_count = ?, truncated = ?, error_code = NULL, error_detail = ? WHERE id = ?",
        out.format,
        out.messages.length,
        out.truncated ? 1 : 0,
        out.notes.length ? out.notes.join(' ') : null,
        ev.id,
      );
      this.event(ev.case_id, 'evidence', ev.id, 'expanded', { format: out.format, note: out.formatNote, messages: out.messages.length, truncated: out.truncated });
      for (const id of toAnalyze) this.d.queue.enqueue('analyze', ev.case_id, id, { priority: 4 });
    });
    if (!toAnalyze.length) this.scheduleCorrelation(ev.case_id);
  }

  // ── analyze ──

  private async analyze(job: Job): Promise<void> {
    const m = this.d.db.get<{ id: string; case_id: string; blob_store: BlobKind; sha256: string; derivation: string; online: number }>(
      'SELECT m.id, m.case_id, m.blob_store, m.sha256, m.derivation, c.online_lookups AS online FROM messages m JOIN cases c ON c.id = m.case_id WHERE m.id = ?',
      job.ref,
    );
    if (!m) return;
    this.d.db.run("UPDATE messages SET status = 'running', attempts = ? WHERE id = ?", job.attempts, m.id);
    this.event(m.case_id, 'message', m.id, 'analysis-started', { attempt: job.attempts });
    const dkimDns = this.d.cfg.allowDkimDns && m.online === 1;
    const out = await this.d.pool.run<AnalyzeOutput>(
      { kind: 'analyze', dataDir: this.d.cfg.dataDir, blobStore: m.blob_store, blobSha256: m.sha256, derivation: m.derivation, intelDbPath: this.d.intelDbPath, dkimDns, thresholds: this.d.cfg.thresholds },
      this.d.cfg.analysisTimeoutMs,
    );
    this.persistAnalysis(m.id, m.case_id, out, { dkimDns });
    this.scheduleCorrelation(m.case_id);
  }

  persistAnalysis(messageId: string, caseId: string, out: AnalyzeOutput, opts: { dkimDns: boolean }): void {
    const r: Report = out.report;
    const json = JSON.stringify(r);
    const configHash = sha256(JSON.stringify({ engine: r.engineVersion, config: analysisConfigFingerprint(this.d.cfg) })).slice(0, 32);
    const now = Date.now();
    const db = this.d.db;
    db.tx(() => {
      if (!db.get('SELECT 1 FROM messages WHERE id = ?', messageId)) return;
      db.run(
        `INSERT OR REPLACE INTO results (message_id, report_gz, report_sha256, fingerprint_json, engine_version, config_hash, intel_snapshot, options_json, duration_ms, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        messageId,
        gzipSync(Buffer.from(json)),
        sha256(json),
        JSON.stringify(r.fingerprint),
        r.engineVersion,
        configHash,
        out.intelSnapshot,
        JSON.stringify({ dkimDns: opts.dkimDns, thresholds: this.d.cfg.thresholds, notes: out.notes }),
        out.durationMs,
        now,
      );
      db.run('DELETE FROM findings WHERE message_id = ?', messageId);
      for (const f of r.findings) {
        db.run('INSERT OR REPLACE INTO findings (message_id, case_id, finding_id, category, severity, weight, title) VALUES (?, ?, ?, ?, ?, ?, ?)', messageId, caseId, f.id, f.category, f.severity, f.weight, f.title);
      }
      db.run('DELETE FROM observations WHERE message_id = ?', messageId);
      for (const ioc of r.iocs ?? []) {
        db.run('INSERT OR IGNORE INTO indicators (type, value) VALUES (?, ?)', ioc.type, ioc.value);
        const ind = db.get<{ id: number }>('SELECT id FROM indicators WHERE type = ? AND value = ?', ioc.type, ioc.value);
        if (!ind) continue;
        db.run('INSERT OR IGNORE INTO observations (message_id, indicator_id, case_id, role, ref, context, suspicious) VALUES (?, ?, ?, ?, ?, ?, ?)', messageId, ind.id, caseId, ioc.role, ioc.ref, ioc.context ?? null, ioc.suspicious ? 1 : 0);
      }
      const cls = r.classification;
      db.run(
        `UPDATE messages SET status = 'analyzed', subject = ?, from_addr = ?, from_name = ?, to_addr = ?, sent_at = ?, message_id = ?, class = ?, severity = ?, confidence = ?,
           score = ?, coverage = ?, verdict = ?, finding_count = ?, ioc_count = ?, engine_version = ?, analyzed_at = ?, error_code = NULL, error_detail = NULL WHERE id = ?`,
        r.summary.subject.slice(0, 1000),
        r.summary.from?.address ?? null,
        r.summary.from?.name?.slice(0, 300) ?? null,
        r.summary.to.map((t) => t.address).join(', ').slice(0, 1000) || null,
        r.summary.date ? Date.parse(r.summary.date) : null,
        r.summary.messageId?.slice(0, 500) ?? null,
        cls?.class ?? null,
        cls?.severity ?? null,
        cls?.confidence ?? null,
        r.score,
        r.coverage?.score ?? null,
        r.verdict,
        r.findings.filter((f) => f.weight > 0).length,
        (r.iocs ?? []).length,
        r.engineVersion,
        now,
        messageId,
      );
      this.event(caseId, 'message', messageId, 'analyzed', { class: cls?.class, score: r.score, ms: out.durationMs, engine: r.engineVersion, intelSnapshot: out.intelSnapshot });
    });
  }

  scheduleCorrelation(caseId: string): void {
    this.d.queue.enqueue('correlate', caseId, caseId, { priority: 8, delayMs: 1500, maxAttempts: 2 });
  }

  // ── correlate ──

  private async correlate(job: Job): Promise<void> {
    const caseId = job.ref;
    if (!this.d.db.get('SELECT 1 FROM cases WHERE id = ?', caseId)) return;
    // Wait while this case still has analyses pending: correlate once the batch has landed.
    const pending = this.d.db.get<{ n: number }>("SELECT COUNT(*) AS n FROM jobs WHERE case_id = ? AND kind IN ('expand', 'analyze') AND status IN ('queued', 'running')", caseId)?.n ?? 0;
    if (pending > 0) {
      this.d.queue.enqueue('correlate', caseId, caseId, { priority: 8, delayMs: 3000, maxAttempts: 2 });
      return;
    }
    const out = await this.d.pool.run<CorrelationResult & { external: { matches: ExternalMatch[]; campaigns: ExternalCampaign[] }; intelSnapshot: string | null }>(
      { kind: 'correlate', caseDbPath: this.d.caseDbPath, intelDbPath: this.d.intelDbPath, caseId, config: {} },
      this.d.cfg.correlateTimeoutMs,
    );
    this.persistCorrelation(caseId, out);
  }

  persistCorrelation(caseId: string, out: CorrelationResult & { external: { matches: ExternalMatch[]; campaigns: ExternalCampaign[] }; intelSnapshot: string | null }): void {
    const db = this.d.db;
    const now = Date.now();
    db.tx(() => {
      if (!db.get('SELECT 1 FROM cases WHERE id = ?', caseId)) return;
      const live = new Set(db.all<{ id: string }>("SELECT id FROM messages WHERE case_id = ? AND status = 'analyzed'", caseId).map((r) => r.id));
      db.run('DELETE FROM edges WHERE case_id = ?', caseId);
      db.run('DELETE FROM clusters WHERE case_id = ?', caseId);
      db.run('DELETE FROM external_campaigns WHERE case_id = ?', caseId);
      db.run('DELETE FROM intel_matches WHERE case_id = ?', caseId);
      db.run('UPDATE messages SET cluster_id = NULL, intel_hits = 0 WHERE case_id = ?', caseId);
      for (const e of out.edges) {
        if (!live.has(e.a) || !live.has(e.b)) continue;
        db.run(
          'INSERT OR REPLACE INTO edges (case_id, a, b, tier, score, evidence_json) VALUES (?, ?, ?, ?, ?, ?)',
          caseId,
          e.a,
          e.b,
          e.tier,
          e.score,
          JSON.stringify({ indicatorScore: e.indicatorScore, similarity: e.similarity, layers: e.layers, hardLink: e.hardLink, shared: e.shared }),
        );
      }
      for (const c of out.clusters) {
        const members = c.members.filter((m) => live.has(m.id));
        if (members.length < 2) continue;
        const ext = out.external.campaigns.filter((x) => x.messages.some((id) => members.some((m) => m.id === id))).map((x) => ({ source: x.source, eventId: x.eventId, name: x.name, assessment: x.assessment, confidence: x.confidence, overlap: x.messages.filter((id) => members.some((m) => m.id === id)).length }));
        db.run(
          `INSERT INTO clusters (id, case_id, label, size, confidence, cohesion, first_seen, last_seen, verdict, profile_json, external_json, method, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          `${caseId.slice(-6)}-${c.id}`,
          caseId,
          c.label,
          members.length,
          c.confidence,
          c.cohesion,
          c.firstSeen,
          c.lastSeen,
          c.verdict,
          JSON.stringify({ clusterKey: c.id, members, density: c.density, exactEdges: c.exactEdges, profile: c.profile, sharedIndicators: c.sharedIndicators }),
          JSON.stringify(ext),
          'louvain over specificity-weighted indicator evidence + layered similarity',
          now,
        );
        for (const m of members) db.run('UPDATE messages SET cluster_id = ? WHERE id = ?', `${caseId.slice(-6)}-${c.id}`, m.id);
      }
      const hits = new Map<string, number>();
      for (const x of out.external.matches) {
        if (!live.has(x.messageId)) continue;
        const ind = db.get<{ id: number }>('SELECT id FROM indicators WHERE type = ? AND value = ?', x.indicatorType, x.value);
        if (!ind) continue;
        db.run(
          'INSERT INTO intel_matches (case_id, message_id, indicator_id, source, match_type, matched_value, record_json, event_id, strength, matched_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
          caseId,
          x.messageId,
          ind.id,
          x.source,
          x.matchType,
          x.matchedValue,
          JSON.stringify({ ...x.record, role: x.role, contextOnly: x.contextOnly }),
          x.eventId,
          x.strength,
          now,
        );
        if (x.strength > 0) hits.set(x.messageId, (hits.get(x.messageId) ?? 0) + 1);
      }
      for (const [id, n] of hits) db.run('UPDATE messages SET intel_hits = ? WHERE id = ?', n, id);
      for (const c of out.external.campaigns) {
        db.run(
          'INSERT OR REPLACE INTO external_campaigns (case_id, source, event_id, name, assessment, confidence, message_count, detail_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
          caseId,
          c.source,
          c.eventId,
          c.name,
          c.assessment,
          c.confidence,
          c.messages.filter((id) => live.has(id)).length,
          JSON.stringify(c),
        );
      }
      db.run('UPDATE cases SET correlated_at = ?, correlation_version = correlation_version + 1 WHERE id = ?', now, caseId);
      this.event(caseId, 'case', caseId, 'correlated', { ...out.stats, intelMatches: out.external.matches.length, externalCampaigns: out.external.campaigns.length, intelSnapshot: out.intelSnapshot });
    });
  }
}
