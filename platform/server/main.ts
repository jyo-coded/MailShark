// MailShark Forensic Platform: command-line entry point.
//   node dist/platform/server.mjs serve                 start the web application (default)
//   node dist/platform/server.mjs create-user <username> <admin|investigator|viewer>   (password on stdin)
//   node dist/platform/server.mjs reset-password <username>                          (password on stdin)
//   node dist/platform/server.mjs intel-sync [source …]  download intelligence feeds now
//   node dist/platform/server.mjs verify-evidence       re-hash every stored blob
//   node dist/platform/server.mjs audit-verify          verify the audit hash chain
import { randomBytes } from 'node:crypto';
import { writeFileSync, rmSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadConfig } from './config';
import { createContext, closeContext, PLATFORM_VERSION } from './context';
import { buildApp } from './app';
import { IntelStore } from './intel/store';
import { CONNECTORS, connector } from './intel/sources';
import { runSync } from './intel/sync';
import type { Role } from './security/auth';

const here = dirname(fileURLToPath(import.meta.url));

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const c of process.stdin) chunks.push(c as Buffer);
  return Buffer.concat(chunks).toString('utf8').replace(/\r?\n$/, '');
}

async function serve(): Promise<void> {
  const cfg = loadConfig();
  const ctx = createContext(cfg, { workerScript: join(here, 'worker.mjs'), intelWorkerScript: join(here, 'intel-worker.mjs'), webRoot: join(here, 'web') });
  const tokenFile = join(cfg.dataDir, 'SETUP_TOKEN');
  if (ctx.auth.userCount() === 0) {
    ctx.setupToken = randomBytes(18).toString('base64url');
    writeFileSync(tokenFile, ctx.setupToken + '\n', { mode: 0o600 });
  } else rmSync(tokenFile, { force: true });
  const app = await buildApp(ctx);
  ctx.processor.start();
  ctx.intel.start();
  const sessions = setInterval(() => ctx.auth.purgeExpired(), 10 * 60_000);
  sessions.unref();
  await app.listen({ host: cfg.host, port: cfg.port });
  const url = `${cfg.tls ? 'https' : 'http'}://${cfg.host === '0.0.0.0' ? 'localhost' : cfg.host}:${cfg.port}`;
  console.log(`MailShark Forensic Platform ${PLATFORM_VERSION} listening on ${url}`);
  console.log(`  data directory: ${cfg.dataDir}`);
  console.log(`  analysis workers: ${cfg.workers} · intelligence auto-sync: ${cfg.intel.autoSync ? 'on' : 'off'}`);
  if (ctx.setupToken) {
    console.log('');
    console.log('  First run: create the administrator account at');
    console.log(`    ${url}/setup`);
    console.log(`  using the one-time setup token: ${ctx.setupToken}`);
    console.log(`  (also written to ${tokenFile})`);
  }
  if (!cfg.tls && cfg.host !== '127.0.0.1' && cfg.host !== 'localhost' && cfg.host !== '::1') {
    console.warn('  WARNING: listening on a non-loopback address without TLS. Set MAILSHARK_TLS_CERT/KEY or put the platform behind an HTTPS reverse proxy.');
  }
  const shutdown = async (sig: string): Promise<void> => {
    console.log(`\n${sig}: shutting down (jobs in progress resume at next start)…`);
    await app.close().catch(() => undefined);
    await closeContext(ctx).catch(() => undefined);
    process.exit(0);
  };
  process.on('SIGINT', () => void shutdown('SIGINT'));
  process.on('SIGTERM', () => void shutdown('SIGTERM'));
}

async function main(): Promise<void> {
  const [cmd = 'serve', ...args] = process.argv.slice(2);
  if (cmd === 'serve') return serve();
  const cfg = loadConfig({ intel: { ...loadConfig().intel } });
  if (cmd === 'create-user' || cmd === 'reset-password') {
    const ctx = createContext(cfg, { workerScript: join(here, 'worker.mjs'), intelWorkerScript: null, webRoot: null });
    try {
      const password = await readStdin();
      if (cmd === 'create-user') {
        const [username, role = 'investigator'] = args;
        if (!username || !['admin', 'investigator', 'viewer'].includes(role)) throw new Error('usage: create-user <username> <admin|investigator|viewer> (password on stdin)');
        const u = await ctx.auth.createUser({ username, displayName: username, password, role: role as Role });
        ctx.audit.record({ username: 'cli', action: 'user.created', target: u.id, details: { username, role, via: 'cli' } });
        console.log(`Created ${role} ${username}.`);
      } else {
        const [username] = args;
        const u = ctx.auth.users().find((x) => x.username.toLowerCase() === (username ?? '').toLowerCase());
        if (!u) throw new Error('No such user.');
        await ctx.auth.setPassword(u.id, password);
        ctx.audit.record({ username: 'cli', action: 'user.password-reset', target: u.id, details: { via: 'cli' } });
        console.log(`Password reset for ${u.username}; existing sessions were ended.`);
      }
    } finally {
      await closeContext(ctx);
    }
    return;
  }
  if (cmd === 'intel-sync') {
    const store = new IntelStore(join(cfg.dataDir, 'intel.db'));
    for (const c of CONNECTORS) store.ensureSource(c.id, c.defaultEnabled);
    const ids = args.length ? args : CONNECTORS.filter((c) => c.sync).sort((a, b) => (a.kind === 'enrichment' ? 0 : 1) - (b.kind === 'enrichment' ? 0 : 1)).map((c) => c.id);
    for (const id of ids) {
      const c = connector(id);
      if (!c?.sync) {
        console.log(`${id}: not a downloadable source`);
        continue;
      }
      if (!store.sourceRow(id)?.enabled) {
        console.log(`${id}: disabled`);
        continue;
      }
      const r = await runSync(store, c, cfg.intel, (m) => console.log(m));
      if (r.status === 'error' || r.status === 'not-configured') console.log(`${id}: ${r.status}${r.error ? ` (${r.error})` : ''}`);
    }
    store.close();
    return;
  }
  if (cmd === 'verify-evidence' || cmd === 'audit-verify') {
    const ctx = createContext(cfg, { workerScript: join(here, 'worker.mjs'), intelWorkerScript: null, webRoot: null });
    try {
      if (cmd === 'audit-verify') {
        const v = ctx.audit.verify();
        console.log(v.ok ? `Audit chain intact: ${v.entries} entries, head ${v.head}` : `AUDIT CHAIN BROKEN at entry ${v.brokenAt}`);
        process.exitCode = v.ok ? 0 : 2;
        return;
      }
      let bad = 0;
      const ev = ctx.db.all<{ sha256: string }>("SELECT DISTINCT sha256 FROM evidence WHERE sha256 != '-'");
      const dv = ctx.db.all<{ sha256: string }>("SELECT DISTINCT sha256 FROM messages WHERE blob_store = 'derived'");
      const rp = ctx.db.all<{ file_sha256: string }>('SELECT DISTINCT file_sha256 FROM reports');
      for (const [kind, list] of [['evidence', ev.map((x) => x.sha256)], ['derived', dv.map((x) => x.sha256)], ['reports', rp.map((x) => x.file_sha256)]] as const) {
        for (const sha of list) {
          const v = await ctx.store.verify(kind, sha);
          if (!v.ok) {
            bad++;
            console.log(`MISMATCH ${kind}/${sha}: ${v.actual ?? 'missing'}`);
          }
        }
        console.log(`${kind}: ${list.length} blobs checked`);
      }
      ctx.audit.record({ username: 'cli', action: 'evidence.verify-all', details: { mismatches: bad } });
      console.log(bad ? `${bad} blob(s) failed verification.` : 'All stored blobs match their SHA-256.');
      process.exitCode = bad ? 2 : 0;
    } finally {
      await closeContext(ctx);
    }
    return;
  }
  console.error(`Unknown command "${cmd}". Commands: serve, create-user, reset-password, intel-sync, verify-evidence, audit-verify`);
  process.exitCode = 1;
}

main().catch((e: unknown) => {
  console.error(e instanceof Error ? e.message : e);
  process.exit(1);
});
