// Shared route helpers: typed errors, authorization guards, parameter parsing, audit shortcuts.
import type { FastifyReply, FastifyRequest } from 'fastify';
import type { AppContext } from '../context';
import { CASE_RANK, caseRole, type CaseRole, type Session, type User } from '../security/auth';

export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    readonly details?: unknown,
  ) {
    super(message);
  }
}

export const notFound = (what = 'Not found'): ApiError => new ApiError(404, 'not-found', what);
export const forbidden = (msg = 'You do not have access to this resource.'): ApiError => new ApiError(403, 'forbidden', msg);
export const badRequest = (msg: string, details?: unknown): ApiError => new ApiError(400, 'bad-request', msg, details);

declare module 'fastify' {
  interface FastifyRequest {
    session?: Session | null;
  }
}

export function requireUser(req: FastifyRequest): User {
  const u = req.session?.user;
  if (!u) throw new ApiError(401, 'unauthenticated', 'Sign in to continue.');
  return u;
}

export function requireAdmin(req: FastifyRequest): User {
  const u = requireUser(req);
  if (u.role !== 'admin') throw forbidden('Administrators only.');
  return u;
}

/** Case-scoped guard. Unknown cases and cases without access both answer 404 (no existence leak). */
export function requireCase(ctx: AppContext, req: FastifyRequest, caseId: string, min: CaseRole = 'viewer'): { user: User; role: CaseRole } {
  const user = requireUser(req);
  if (!/^case_[a-f0-9-]{36}$/.test(caseId)) throw notFound('Case not found.');
  const role = caseRole(ctx.db, user, caseId);
  if (!role) throw notFound('Case not found.');
  if (CASE_RANK[role] < CASE_RANK[min]) throw forbidden(min === 'lead' ? 'Only the case lead or an administrator can do this.' : 'Your role in this case is read-only.');
  return { user, role };
}

export function ip(req: FastifyRequest): string | null {
  return req.ip ?? null;
}

export function audit(ctx: AppContext, req: FastifyRequest, action: string, a: { caseId?: string | null; target?: string | null; details?: unknown } = {}): void {
  const u = req.session?.user;
  ctx.audit.record({ userId: u?.id ?? null, username: u?.username ?? null, action, caseId: a.caseId ?? null, target: a.target ?? null, details: a.details, ip: ip(req) });
}

export function int(v: unknown, def: number, min: number, max: number): number {
  const n = typeof v === 'string' && v.trim() !== '' ? Number(v) : typeof v === 'number' ? v : NaN;
  if (!Number.isFinite(n)) return def;
  return Math.min(max, Math.max(min, Math.trunc(n)));
}

export function str(v: unknown, max = 500): string | null {
  if (typeof v !== 'string') return null;
  const s = v.trim();
  return s ? s.slice(0, max) : null;
}

export function list(v: unknown, allowed?: readonly string[]): string[] {
  const raw = typeof v === 'string' ? v.split(',') : Array.isArray(v) ? v.map(String) : [];
  const out = raw.map((s) => s.trim()).filter(Boolean);
  return allowed ? out.filter((s) => allowed.includes(s)) : out;
}

/** RFC 6266 Content-Disposition with an ASCII fallback and an RFC 5987 UTF-8 name. */
export function attachmentHeader(name: string): string {
  const clean = name.replace(/[\u0000-\u001f\u007f"\\/]/g, '_').slice(0, 180) || 'download';
  const ascii = clean.replace(/[^\x20-\x7e]/g, '_');
  return `attachment; filename="${ascii}"; filename*=UTF-8''${encodeURIComponent(clean)}`;
}

export function sendJsonDownload(reply: FastifyReply, name: string, data: Buffer, type: string): FastifyReply {
  return reply.header('content-type', type).header('content-disposition', attachmentHeader(name)).header('cache-control', 'no-store').send(data);
}

/** Display-safe version of an untrusted file name (control characters removed, length capped). */
export function cleanFileName(name: string | undefined | null): string {
  // eslint-disable-next-line no-control-regex
  return (name ?? '').replace(/[\u0000-\u001f\u007f‪-‮⁦-⁩]/g, '').trim().slice(0, 255) || 'unnamed';
}
