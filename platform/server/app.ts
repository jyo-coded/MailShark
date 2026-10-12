// HTTP application: plugins, security headers, error handling, routes, static web client.
import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import Fastify, { type FastifyInstance } from 'fastify';
import cookie from '@fastify/cookie';
import multipart from '@fastify/multipart';
import rateLimit from '@fastify/rate-limit';
import fastifyStatic from '@fastify/static';
import type { AppContext } from './context';
import { ApiError } from './api/util';
import { registerSessionHook } from './api/session';
import { registerCore } from './api/core';
import { registerEvidence } from './api/evidence';
import { registerMessages } from './api/messages';
import { registerInsight } from './api/insight';

const CSP = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self' data:",
  "font-src 'self'",
  "connect-src 'self'",
  "object-src 'none'",
  "frame-src 'none'",
  "frame-ancestors 'none'",
  "base-uri 'none'",
  "form-action 'self'",
].join('; ');

export async function buildApp(ctx: AppContext): Promise<FastifyInstance> {
  const https = ctx.cfg.tls ? { key: readFileSync(ctx.cfg.tls.keyPath), cert: readFileSync(ctx.cfg.tls.certPath) } : null;
  const app = (https
    ? Fastify({ https, logger: { level: ctx.cfg.logLevel }, disableRequestLogging: true, bodyLimit: 1_048_576, trustProxy: process.env['MAILSHARK_TRUST_PROXY'] === '1' })
    : Fastify({ logger: { level: ctx.cfg.logLevel }, disableRequestLogging: true, bodyLimit: 1_048_576, trustProxy: process.env['MAILSHARK_TRUST_PROXY'] === '1' })) as unknown as FastifyInstance;

  await app.register(cookie);
  await app.register(multipart, { throwFileSizeLimit: false, limits: { files: ctx.cfg.limits.filesPerBatch, fileSize: ctx.cfg.limits.fileBytes + 1, fields: 10, parts: ctx.cfg.limits.filesPerBatch + 10 } });
  await app.register(rateLimit, { global: false, keyGenerator: (req) => req.ip });

  app.addHook('onSend', async (req, reply, payload) => {
    reply.header('x-content-type-options', 'nosniff');
    reply.header('referrer-policy', 'no-referrer');
    reply.header('x-frame-options', 'DENY');
    reply.header('cross-origin-opener-policy', 'same-origin');
    reply.header('cross-origin-resource-policy', 'same-origin');
    reply.header('permissions-policy', 'camera=(), microphone=(), geolocation=(), payment=(), usb=()');
    reply.header('content-security-policy', CSP);
    if (ctx.cfg.tls) reply.header('strict-transport-security', 'max-age=31536000');
    if (req.url.startsWith('/api/') && !reply.hasHeader('cache-control')) reply.header('cache-control', 'no-store');
    return payload;
  });

  app.setErrorHandler((err: Error & { statusCode?: number; code?: string; validation?: unknown }, req, reply) => {
    if (err instanceof ApiError) return reply.code(err.status).send({ error: { code: err.code, message: err.message, ...(err.details !== undefined ? { details: err.details } : {}) } });
    if (err.statusCode === 429) return reply.code(429).send({ error: { code: 'rate-limited', message: 'Too many requests. Wait a moment and try again.' } });
    if (err.validation) return reply.code(400).send({ error: { code: 'bad-request', message: err.message } });
    if (err.statusCode && err.statusCode >= 400 && err.statusCode < 500) return reply.code(err.statusCode).send({ error: { code: err.code ?? 'bad-request', message: err.message } });
    const ref = Math.random().toString(36).slice(2, 10);
    ctx.log('error', `[http] ${req.method} ${req.url.split('?')[0]} failed (ref ${ref}): ${err.stack ?? err.message}`);
    return reply.code(500).send({ error: { code: 'internal', message: `Unexpected server error (reference ${ref}). Details are in the server log.` } });
  });

  registerSessionHook(app, ctx);
  registerCore(app, ctx);
  registerEvidence(app, ctx);
  registerMessages(app, ctx);
  registerInsight(app, ctx);

  const web = ctx.webRoot && existsSync(join(ctx.webRoot, 'index.html')) ? ctx.webRoot : null;
  if (web) {
    await app.register(fastifyStatic, { root: web, prefix: '/', index: 'index.html', wildcard: false, cacheControl: true, maxAge: 0, etag: true });
  }
  app.setNotFoundHandler((req, reply) => {
    if (req.url.startsWith('/api/')) return reply.code(404).send({ error: { code: 'not-found', message: 'No such API endpoint.' } });
    if (web && req.method === 'GET' && !/\.[a-z0-9]{1,5}$/i.test(req.url.split('?')[0] ?? '')) return reply.header('cache-control', 'no-store').sendFile('index.html');
    return reply.code(404).type('text/plain').send('Not found');
  });
  return app;
}
