// Session cookie handling and the authentication / CSRF hook for /api routes.
import type { FastifyInstance, FastifyReply } from 'fastify';
import type { AppContext } from '../context';
import { ApiError } from './util';

export const SESSION_COOKIE = 'ms_session';

export function setSessionCookie(reply: FastifyReply, ctx: AppContext, token: string, expiresAt: number): void {
  reply.setCookie(SESSION_COOKIE, token, {
    httpOnly: true,
    sameSite: 'strict',
    secure: ctx.cfg.cookieSecure,
    path: '/',
    expires: new Date(expiresAt),
  });
}

export function clearSessionCookie(reply: FastifyReply, ctx: AppContext): void {
  reply.clearCookie(SESSION_COOKIE, { path: '/', httpOnly: true, sameSite: 'strict', secure: ctx.cfg.cookieSecure });
}

const PUBLIC = new Set(['/api/health', '/api/setup', '/api/auth/login', '/api/auth/session', '/api/auth/logout']);

export function registerSessionHook(app: FastifyInstance, ctx: AppContext): void {
  app.addHook('preHandler', async (req) => {
    if (!req.url.startsWith('/api/')) return;
    const token = req.cookies[SESSION_COOKIE];
    req.session = ctx.auth.session(token);
    const path = req.url.split('?')[0] as string;
    const mutating = req.method !== 'GET' && req.method !== 'HEAD' && req.method !== 'OPTIONS';
    if (!PUBLIC.has(path) && !req.session) throw new ApiError(401, 'unauthenticated', 'Sign in to continue.');
    // CSRF: SameSite=Strict already blocks cross-site cookies; the token header is defence in depth
    // (and protects against same-site attackers such as other apps on the host).
    if (mutating && req.session && path !== '/api/auth/login') {
      const header = req.headers['x-csrf-token'];
      if (typeof header !== 'string' || header !== req.session.csrf) throw new ApiError(403, 'csrf', 'Missing or invalid CSRF token. Reload the page and try again.');
    }
  });
}
