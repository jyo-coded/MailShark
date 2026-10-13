// System, setup, authentication, users and cases.
import { randomUUID, timingSafeEqual } from 'node:crypto';
import type { FastifyInstance } from 'fastify';
import { PLATFORM_VERSION, type AppContext } from '../context';
import { ENGINE_VERSION } from '../../../engine/src/analyze';
import { ApiError, audit, badRequest, forbidden, int, notFound, requireAdmin, requireCase, requireUser, str } from './util';
import type { CaseRole, Role } from '../security/auth';
import { setSessionCookie, clearSessionCookie, SESSION_COOKIE } from './session';

const ROLES: Role[] = ['admin', 'investigator', 'viewer'];
const CASE_ROLES: CaseRole[] = ['lead', 'investigator', 'viewer'];

function safeEqual(a: string, b: string): boolean {
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
}

export function registerCore(app: FastifyInstance, ctx: AppContext): void {
  // ── System ──
  app.get('/api/health', async () => {
    let dbOk = true;
    try {
      ctx.db.get('SELECT 1');
    } catch {
      dbOk = false;
    }
    const sources = ctx.intel.sources().filter((s) => s.kind !== 'lookup');
    return {
      status: dbOk ? 'ok' : 'degraded',
      version: PLATFORM_VERSION,
      engine: ENGINE_VERSION,
      uptimeSec: Math.round((Date.now() - ctx.startedAt) / 1000),
      database: dbOk ? 'ok' : 'error',
      workers: ctx.pool.stats(),
      queue: ctx.queue.depth(),
      intel: {
        current: sources.filter((s) => s.freshness === 'current').length,
        stale: sources.filter((s) => s.freshness === 'stale').length,
        unavailable: sources.filter((s) => s.freshness === 'unavailable' || s.freshness === 'never-synced').length,
        total: sources.length,
      },
    };
  });

  app.get('/api/setup', async () => ({ needed: ctx.auth.userCount() === 0 }));

  app.post('/api/setup', { config: { rateLimit: { max: 10, timeWindow: '15 minutes' } } }, async (req) => {
    const b = (req.body ?? {}) as Record<string, unknown>;
    if (ctx.auth.userCount() > 0 || !ctx.setupToken) throw forbidden('Setup has already been completed.');
    const token = str(b['token'], 200) ?? '';
    if (!safeEqual(token, ctx.setupToken)) throw new ApiError(403, 'invalid-setup-token', 'The setup token is not valid. It is printed in the server console at start-up.');
    let user;
    try {
      user = await ctx.auth.createUser({ username: str(b['username'], 40) ?? '', displayName: str(b['displayName'], 100) ?? '', password: typeof b['password'] === 'string' ? b['password'] : '', role: 'admin' });
    } catch (e) {
      throw badRequest(e instanceof Error ? e.message : 'Invalid input.');
    }
    ctx.setupToken = null;
    ctx.audit.record({ userId: user.id, username: user.username, action: 'setup.admin-created', ip: req.ip });
    return { ok: true };
  });

  // ── Authentication ──
  app.post('/api/auth/login', { config: { rateLimit: { max: 20, timeWindow: '15 minutes' } } }, async (req, reply) => {
    const b = (req.body ?? {}) as Record<string, unknown>;
    const username = str(b['username'], 40) ?? '';
    const password = typeof b['password'] === 'string' ? b['password'].slice(0, 256) : '';
    const r = await ctx.auth.login(username, password);
    if (!r.ok) {
      ctx.audit.record({ username: username || null, action: 'auth.login-failed', details: { reason: r.reason }, ip: req.ip });
      throw new ApiError(401, r.reason === 'locked' ? 'locked' : 'invalid-credentials', r.reason === 'locked' ? 'Too many failed attempts: the account is locked for 15 minutes.' : 'Invalid username or password.');
    }
    const s = ctx.auth.createSession(r.user.id, req.ip, req.headers['user-agent'] ?? null);
    setSessionCookie(reply, ctx, s.token, s.expiresAt);
    ctx.audit.record({ userId: r.user.id, username: r.user.username, action: 'auth.login', ip: req.ip });
    return { user: publicUser(r.user), csrf: s.csrf };
  });

  app.post('/api/auth/logout', async (req, reply) => {
    if (req.session) {
      ctx.auth.destroySession(req.session.tokenHash);
      audit(ctx, req, 'auth.logout');
    }
    clearSessionCookie(reply, ctx);
    return { ok: true };
  });

  app.get('/api/auth/session', async (req) => {
    if (!req.session) return { user: null, csrf: null, setupNeeded: ctx.auth.userCount() === 0 };
    const l = ctx.cfg.limits;
    return {
      user: publicUser(req.session.user),
      csrf: req.session.csrf,
      setupNeeded: false,
      expiresAt: req.session.expiresAt,
      // What the client needs to validate uploads before sending them (the server enforces the same limits).
      platform: {
        version: PLATFORM_VERSION,
        engine: ENGINE_VERSION,
        limits: { filesPerBatch: l.filesPerBatch, fileBytes: l.fileBytes, batchBytes: l.batchBytes, messagesPerContainer: l.messagesPerContainer },
        formats: ['eml', 'emlx', 'mbox', 'msg'],
        onlineLookupsAllowed: ctx.cfg.allowOnlineLookups,
        thresholds: ctx.cfg.thresholds,
      },
    };
  });

  app.post('/api/auth/password', async (req) => {
    const user = requireUser(req);
    const b = (req.body ?? {}) as Record<string, unknown>;
    if (!(await ctx.auth.checkPassword(user.id, typeof b['current'] === 'string' ? b['current'] : ''))) throw new ApiError(400, 'invalid-credentials', 'The current password is not correct.');
    try {
      await ctx.auth.setPassword(user.id, typeof b['password'] === 'string' ? b['password'] : '');
    } catch (e) {
      throw badRequest(e instanceof Error ? e.message : 'Invalid password.');
    }
    audit(ctx, req, 'auth.password-changed', { target: user.id });
    return { ok: true, reauthenticate: true };
  });

  // ── Users (administration) ──
  app.get('/api/users', async (req) => {
    const u = requireUser(req);
    // Investigators need the user list to add case members; only admins see roles of everyone.
    return ctx.auth.users().filter((x) => u.role === 'admin' || !x.disabled).map((x) => (u.role === 'admin' ? publicUser(x) : { id: x.id, username: x.username, displayName: x.display_name }));
  });

  app.post('/api/users', async (req) => {
    requireAdmin(req);
    const b = (req.body ?? {}) as Record<string, unknown>;
    const role = str(b['role'], 20) as Role;
    if (!ROLES.includes(role)) throw badRequest('Role must be admin, investigator or viewer.');
    try {
      const user = await ctx.auth.createUser({ username: str(b['username'], 40) ?? '', displayName: str(b['displayName'], 100) ?? '', password: typeof b['password'] === 'string' ? b['password'] : '', role });
      audit(ctx, req, 'user.created', { target: user.id, details: { username: user.username, role } });
      return publicUser(user);
    } catch (e) {
      throw badRequest(e instanceof Error ? e.message : 'Invalid input.');
    }
  });

  app.patch('/api/users/:id', async (req) => {
    const admin = requireAdmin(req);
    const { id } = req.params as { id: string };
    const target = ctx.auth.user(id);
    if (!target) throw notFound('User not found.');
    const b = (req.body ?? {}) as Record<string, unknown>;
    const role = b['role'] !== undefined ? (str(b['role'], 20) as Role) : undefined;
    if (role !== undefined && !ROLES.includes(role)) throw badRequest('Invalid role.');
    if (id === admin.id && (role !== undefined && role !== 'admin' || b['disabled'] === true)) throw badRequest('You cannot demote or disable your own account.');
    ctx.auth.updateUser(id, { ...(typeof b['displayName'] === 'string' ? { displayName: b['displayName'] } : {}), ...(role ? { role } : {}), ...(typeof b['disabled'] === 'boolean' ? { disabled: b['disabled'] } : {}) });
    audit(ctx, req, 'user.updated', { target: id, details: { role, disabled: b['disabled'] } });
    return publicUser(ctx.auth.user(id) as NonNullable<ReturnType<typeof ctx.auth.user>>);
  });

  app.post('/api/users/:id/password', async (req) => {
    requireAdmin(req);
    const { id } = req.params as { id: string };
    if (!ctx.auth.user(id)) throw notFound('User not found.');
    const b = (req.body ?? {}) as Record<string, unknown>;
    try {
      await ctx.auth.setPassword(id, typeof b['password'] === 'string' ? b['password'] : '');
    } catch (e) {
      throw badRequest(e instanceof Error ? e.message : 'Invalid password.');
    }
    audit(ctx, req, 'user.password-reset', { target: id });
    return { ok: true };
  });

  // ── Cases ──
  app.get('/api/cases', async (req) => {
    const user = requireUser(req);
    const rows = ctx.db.all<CaseRow & { my_role: CaseRole | null }>(
      user.role === 'admin'
        ? `SELECT c.*, 'lead' AS my_role FROM cases c ORDER BY c.updated_at DESC`
        : `SELECT c.*, cm.role AS my_role FROM cases c JOIN case_members cm ON cm.case_id = c.id AND cm.user_id = ? ORDER BY c.updated_at DESC`,
      ...(user.role === 'admin' ? [] : [user.id]),
    );
    return rows.map((c) => caseSummary(ctx, c, user.role === 'viewer' ? 'viewer' : (c.my_role as CaseRole)));
  });

  app.post('/api/cases', async (req) => {
    const user = requireUser(req);
    if (user.role === 'viewer') throw forbidden('Viewers cannot create cases.');
    const b = (req.body ?? {}) as Record<string, unknown>;
    const name = str(b['name'], 200);
    if (!name) throw badRequest('A case name is required.');
    const id = `case_${randomUUID()}`;
    const now = Date.now();
    ctx.db.tx(() => {
      ctx.db.run(
        'INSERT INTO cases (id, name, reference, description, status, created_by, created_at, updated_at, retention_until, online_lookups) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
        id,
        name,
        str(b['reference'], 100),
        str(b['description'], 4000),
        'open',
        user.id,
        now,
        now,
        typeof b['retentionUntil'] === 'number' ? b['retentionUntil'] : null,
        b['onlineLookups'] === true && ctx.cfg.allowOnlineLookups ? 1 : 0,
      );
      ctx.db.run('INSERT INTO case_members (case_id, user_id, role, added_at) VALUES (?, ?, ?, ?)', id, user.id, 'lead', now);
    });
    audit(ctx, req, 'case.created', { caseId: id, details: { name } });
    const row = ctx.db.get<CaseRow>('SELECT * FROM cases WHERE id = ?', id) as CaseRow;
    return caseSummary(ctx, row, 'lead');
  });

  app.get('/api/cases/:id', async (req) => {
    const { id } = req.params as { id: string };
    const { role } = requireCase(ctx, req, id);
    return caseSummary(ctx, ctx.db.get<CaseRow>('SELECT * FROM cases WHERE id = ?', id) as CaseRow, role);
  });

  app.patch('/api/cases/:id', async (req) => {
    const { id } = req.params as { id: string };
    requireCase(ctx, req, id, 'lead');
    const b = (req.body ?? {}) as Record<string, unknown>;
    const sets: string[] = [];
    const vals: (string | number | null)[] = [];
    const set = (col: string, v: string | number | null): void => {
      sets.push(`${col} = ?`);
      vals.push(v);
    };
    if (typeof b['name'] === 'string') set('name', str(b['name'], 200) ?? 'Untitled case');
    if (b['reference'] !== undefined) set('reference', str(b['reference'], 100));
    if (b['description'] !== undefined) set('description', str(b['description'], 4000));
    if (b['status'] !== undefined) {
      if (!['open', 'closed', 'archived'].includes(String(b['status']))) throw badRequest('Invalid status.');
      set('status', String(b['status']));
    }
    if (b['legalHold'] !== undefined) set('legal_hold', b['legalHold'] === true ? 1 : 0);
    if (b['retentionUntil'] !== undefined) set('retention_until', typeof b['retentionUntil'] === 'number' ? b['retentionUntil'] : null);
    if (b['onlineLookups'] !== undefined) {
      if (b['onlineLookups'] === true && !ctx.cfg.allowOnlineLookups) throw badRequest('Online lookups are disabled on this server (MAILSHARK_ALLOW_ONLINE_LOOKUPS=false).');
      set('online_lookups', b['onlineLookups'] === true ? 1 : 0);
    }
    if (!sets.length) throw badRequest('Nothing to update.');
    set('updated_at', Date.now());
    ctx.db.run(`UPDATE cases SET ${sets.join(', ')} WHERE id = ?`, ...vals, id);
    audit(ctx, req, 'case.updated', { caseId: id, details: b });
    const { role } = requireCase(ctx, req, id);
    return caseSummary(ctx, ctx.db.get<CaseRow>('SELECT * FROM cases WHERE id = ?', id) as CaseRow, role);
  });

  app.delete('/api/cases/:id', async (req) => {
    const { id } = req.params as { id: string };
    requireCase(ctx, req, id, 'lead');
    const c = ctx.db.get<CaseRow>('SELECT * FROM cases WHERE id = ?', id) as CaseRow;
    if (c.legal_hold) throw new ApiError(409, 'legal-hold', 'The case is under legal hold and cannot be deleted.');
    const b = (req.body ?? {}) as Record<string, unknown>;
    if (str(b['confirm'], 200) !== c.name) throw badRequest('Type the case name to confirm deletion.');
    ctx.queue.cancelForCase(id);
    const evidence = ctx.db.all<{ sha256: string; original_name: string }>('SELECT DISTINCT sha256, original_name FROM evidence WHERE case_id = ?', id);
    const derived = ctx.db.all<{ sha256: string }>("SELECT DISTINCT sha256 FROM messages WHERE case_id = ? AND blob_store = 'derived'", id);
    const reports = ctx.db.all<{ file_sha256: string }>('SELECT file_sha256 FROM reports WHERE case_id = ?', id);
    ctx.db.tx(() => {
      ctx.db.run('DELETE FROM intel_matches WHERE case_id = ?', id);
      ctx.db.run('DELETE FROM observations WHERE case_id = ?', id);
      ctx.db.run('DELETE FROM findings WHERE case_id = ?', id);
      ctx.db.run('DELETE FROM events WHERE case_id = ?', id);
      ctx.db.run('DELETE FROM cases WHERE id = ?', id);
    });
    // Remove stored bytes no other case references.
    for (const e of evidence) if (!ctx.db.get('SELECT 1 FROM evidence WHERE sha256 = ?', e.sha256)) await ctx.store.remove('evidence', e.sha256);
    for (const d of derived) if (!ctx.db.get("SELECT 1 FROM messages WHERE sha256 = ? AND blob_store = 'derived'", d.sha256)) await ctx.store.remove('derived', d.sha256);
    for (const r of reports) if (!ctx.db.get('SELECT 1 FROM reports WHERE file_sha256 = ?', r.file_sha256)) await ctx.store.remove('reports', r.file_sha256);
    audit(ctx, req, 'case.deleted', { caseId: id, details: { name: c.name, reference: c.reference, evidence: evidence.map((e) => ({ sha256: e.sha256, name: e.original_name })) } });
    return { ok: true };
  });

  app.get('/api/cases/:id/members', async (req) => {
    const { id } = req.params as { id: string };
    requireCase(ctx, req, id);
    return ctx.db.all<{ user_id: string; username: string; display_name: string; role: CaseRole; added_at: number }>(
      'SELECT cm.user_id, u.username, u.display_name, cm.role, cm.added_at FROM case_members cm JOIN users u ON u.id = cm.user_id WHERE cm.case_id = ? ORDER BY cm.added_at',
      id,
    );
  });

  app.post('/api/cases/:id/members', async (req) => {
    const { id } = req.params as { id: string };
    requireCase(ctx, req, id, 'lead');
    const b = (req.body ?? {}) as Record<string, unknown>;
    const userId = str(b['userId'], 60) ?? '';
    const role = str(b['role'], 20) as CaseRole;
    if (!CASE_ROLES.includes(role)) throw badRequest('Role must be lead, investigator or viewer.');
    const target = ctx.auth.user(userId);
    if (!target || target.disabled) throw notFound('User not found.');
    ctx.db.run('INSERT INTO case_members (case_id, user_id, role, added_at) VALUES (?, ?, ?, ?) ON CONFLICT(case_id, user_id) DO UPDATE SET role = excluded.role', id, userId, role, Date.now());
    audit(ctx, req, 'case.member-set', { caseId: id, target: userId, details: { role } });
    return { ok: true };
  });

  app.delete('/api/cases/:id/members/:userId', async (req) => {
    const { id, userId } = req.params as { id: string; userId: string };
    requireCase(ctx, req, id, 'lead');
    const leads = ctx.db.get<{ n: number }>("SELECT COUNT(*) AS n FROM case_members WHERE case_id = ? AND role = 'lead' AND user_id != ?", id, userId)?.n ?? 0;
    const isLead = ctx.db.get<{ role: string }>('SELECT role FROM case_members WHERE case_id = ? AND user_id = ?', id, userId)?.role === 'lead';
    if (isLead && leads === 0) throw badRequest('A case needs at least one lead.');
    ctx.db.run('DELETE FROM case_members WHERE case_id = ? AND user_id = ?', id, userId);
    audit(ctx, req, 'case.member-removed', { caseId: id, target: userId });
    return { ok: true };
  });

  void int;
  void SESSION_COOKIE;
}

export interface CaseRow {
  id: string;
  name: string;
  reference: string | null;
  description: string | null;
  status: string;
  created_by: string;
  created_at: number;
  updated_at: number;
  legal_hold: number;
  retention_until: number | null;
  online_lookups: number;
  correlation_version: number;
  correlated_at: number | null;
}

export function publicUser(u: { id: string; username: string; display_name: string; role: Role; disabled: number; created_at: number; last_login_at: number | null }): Record<string, unknown> {
  return { id: u.id, username: u.username, displayName: u.display_name, role: u.role, disabled: !!u.disabled, createdAt: u.created_at, lastLoginAt: u.last_login_at };
}

export function caseSummary(ctx: AppContext, c: CaseRow, role: CaseRole): Record<string, unknown> {
  const counts = ctx.db.get<Record<string, number | null>>(
    `SELECT COUNT(*) AS messages,
       SUM(status = 'analyzed') AS analyzed, SUM(status IN ('queued', 'running')) AS pending, SUM(status = 'failed') AS failed, SUM(status = 'duplicate') AS duplicates,
       SUM(class = 'malicious') AS malicious, SUM(class = 'suspicious') AS suspicious, SUM(class = 'benign') AS benign, SUM(class = 'inconclusive') AS inconclusive,
       SUM(intel_hits > 0) AS intel, MAX(analyzed_at) AS last_analyzed
     FROM messages WHERE case_id = ?`,
    c.id,
  ) ?? {};
  const evidence = ctx.db.get<{ n: number; bytes: number | null }>('SELECT COUNT(*) AS n, SUM(size) AS bytes FROM evidence WHERE case_id = ?', c.id) ?? { n: 0, bytes: 0 };
  const clusters = ctx.db.get<{ n: number; threats: number | null }>("SELECT COUNT(*) AS n, SUM(verdict != 'bulk') AS threats FROM clusters WHERE case_id = ?", c.id) ?? { n: 0, threats: 0 };
  const external = ctx.db.get<{ n: number }>("SELECT COUNT(*) AS n FROM external_campaigns WHERE case_id = ? AND assessment = 'reported-association'", c.id)?.n ?? 0;
  const creator = ctx.auth.user(c.created_by);
  return {
    id: c.id,
    name: c.name,
    reference: c.reference,
    description: c.description,
    status: c.status,
    createdAt: c.created_at,
    updatedAt: c.updated_at,
    createdBy: creator ? { id: creator.id, username: creator.username, displayName: creator.display_name } : null,
    legalHold: !!c.legal_hold,
    retentionUntil: c.retention_until,
    onlineLookups: !!c.online_lookups,
    correlatedAt: c.correlated_at,
    myRole: role,
    counts: {
      evidence: evidence.n,
      evidenceBytes: evidence.bytes ?? 0,
      messages: counts['messages'] ?? 0,
      analyzed: counts['analyzed'] ?? 0,
      pending: counts['pending'] ?? 0,
      failed: counts['failed'] ?? 0,
      duplicates: counts['duplicates'] ?? 0,
      malicious: counts['malicious'] ?? 0,
      suspicious: counts['suspicious'] ?? 0,
      benign: counts['benign'] ?? 0,
      inconclusive: counts['inconclusive'] ?? 0,
      withIntel: counts['intel'] ?? 0,
      clusters: clusters.n,
      threatClusters: clusters.threats ?? 0,
      externalCampaigns: external,
    },
    lastAnalyzedAt: counts['last_analyzed'] ?? null,
  };
}
