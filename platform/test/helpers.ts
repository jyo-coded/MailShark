// Test harness: builds the analysis worker once, creates isolated platform instances in temp
// directories and drives the HTTP API in-process (Fastify inject: real routing, no sockets).
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { build } from 'esbuild';
import type { FastifyInstance } from 'fastify';
import { loadConfig, type Config } from '../server/config';
import { createContext, type AppContext } from '../server/context';
import { buildApp } from '../server/app';

const root = resolve(__dirname, '..', '..');
let worker: Promise<string> | null = null;

export function workerScript(): Promise<string> {
  worker ??= (async () => {
    const out = join(mkdtempSync(join(tmpdir(), 'ms-worker-')), 'worker.mjs');
    await build({
      entryPoints: [join(root, 'platform', 'server', 'jobs', 'worker.ts')],
      outfile: out,
      bundle: true,
      platform: 'node',
      format: 'esm',
      target: 'node22',
      logLevel: 'silent',
      banner: { js: "import { createRequire as __r } from 'node:module'; const require = __r(import.meta.url);" },
    });
    return out;
  })();
  return worker;
}

export interface TestPlatform {
  ctx: AppContext;
  app: FastifyInstance;
  dir: string;
  close: () => Promise<void>;
}

export async function startPlatform(tweak: (c: Config) => void = () => undefined): Promise<TestPlatform> {
  const dir = mkdtempSync(join(tmpdir(), 'ms-platform-'));
  const cfg = loadConfig({ dataDir: dir });
  cfg.workers = 2;
  cfg.intel.autoSync = false;
  cfg.allowDkimDns = false;
  tweak(cfg);
  const ctx = createContext(cfg, { workerScript: await workerScript(), intelWorkerScript: null, webRoot: null, log: () => undefined });
  ctx.setupToken = 'setup-token-for-tests-0123456789';
  const app = await buildApp(ctx);
  ctx.processor.start();
  return {
    ctx,
    app,
    dir,
    close: async () => {
      await app.close();
      await ctx.processor.stop();
      await ctx.pool.close();
      await ctx.intel.stop();
      ctx.db.close();
    },
  };
}

export class Client {
  cookie = '';
  csrf = '';
  constructor(private readonly app: FastifyInstance) {}

  async call(method: 'GET' | 'POST' | 'PATCH' | 'DELETE', url: string, body?: unknown, headers: Record<string, string> = {}): Promise<{ status: number; json: () => any; body: string; raw: Buffer; headers: Record<string, unknown> }> {
    const res = await this.app.inject({
      method,
      url,
      ...(body === undefined ? {} : Buffer.isBuffer(body) ? { payload: body } : { payload: body as object }),
      headers: { ...(this.cookie ? { cookie: this.cookie } : {}), ...(this.csrf && method !== 'GET' ? { 'x-csrf-token': this.csrf } : {}), ...headers },
    });
    const set = res.headers['set-cookie'];
    const first = Array.isArray(set) ? set[0] : set;
    if (typeof first === 'string' && first.startsWith('ms_session=')) this.cookie = first.split(';')[0] as string;
    return { status: res.statusCode, json: () => JSON.parse(res.body), body: res.body, raw: res.rawPayload, headers: res.headers as Record<string, unknown> };
  }

  async login(username: string, password: string): Promise<void> {
    const r = await this.call('POST', '/api/auth/login', { username, password });
    if (r.status !== 200) throw new Error(`login failed: ${r.status} ${r.body}`);
    this.csrf = r.json().csrf;
  }
}

export function multipart(files: { name: string; content: Buffer | string; type?: string }[], fields: Record<string, string> = {}): { payload: Buffer; headers: Record<string, string> } {
  const boundary = `----mstest${Math.random().toString(16).slice(2)}`;
  const parts: Buffer[] = [];
  for (const [k, v] of Object.entries(fields)) parts.push(Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="${k}"\r\n\r\n${v}\r\n`));
  for (const f of files) {
    parts.push(Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="files"; filename="${f.name}"\r\nContent-Type: ${f.type ?? 'message/rfc822'}\r\n\r\n`));
    parts.push(Buffer.isBuffer(f.content) ? f.content : Buffer.from(f.content, 'latin1'));
    parts.push(Buffer.from('\r\n'));
  }
  parts.push(Buffer.from(`--${boundary}--\r\n`));
  return { payload: Buffer.concat(parts), headers: { 'content-type': `multipart/form-data; boundary=${boundary}` } };
}

export async function waitFor(fn: () => Promise<boolean>, timeoutMs = 120_000, stepMs = 250): Promise<void> {
  const end = Date.now() + timeoutMs;
  while (Date.now() < end) {
    if (await fn()) return;
    await new Promise((r) => setTimeout(r, stepMs));
  }
  throw new Error('timed out waiting for condition');
}
