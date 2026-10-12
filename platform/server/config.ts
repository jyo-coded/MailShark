// Platform configuration: environment variables only, validated at start-up.
// Every variable is documented in docs/platform/README.md (Configuration).
import { mkdirSync } from 'node:fs';
import { availableParallelism } from 'node:os';
import { resolve } from 'node:path';

export interface IntelConfig {
  /** Scheduled downloads of the bulk feeds. */
  autoSync: boolean;
  otxApiKey: string | null;
  virusTotalApiKey: string | null;
  mispUrl: string | null;
  mispApiKey: string | null;
  mispVerifyTls: boolean;
  abusechAuthKey: string | null;
  phishtankAppKey: string | null;
  /** Download the full MalwareBazaar hash export (~225 MB zip) instead of the 48-hour window. */
  bazaarFull: boolean;
  /** Download Phishing.Database URL lists (~65 MB) in addition to the domain list. */
  phishingDbLinks: boolean;
  /** Oldest MISP feed events to import (YYYY-MM-DD). */
  mispFeedSince: string;
  /** Max MISP feed events fetched per sync run (politeness towards feed hosts). */
  mispFeedBatch: number;
}

export interface Config {
  dataDir: string;
  host: string;
  port: number;
  tls: { certPath: string; keyPath: string } | null;
  cookieSecure: boolean;
  limits: {
    filesPerBatch: number;
    fileBytes: number;
    batchBytes: number;
    messagesPerContainer: number;
    rawViewBytes: number;
  };
  workers: number;
  analysisTimeoutMs: number;
  expandTimeoutMs: number;
  correlateTimeoutMs: number;
  workerHeapMb: number;
  session: { idleMinutes: number; maxHours: number };
  thresholds: { caution: number; danger: number; coverageFloor: number };
  /** Global switch for anything that sends case indicators to third parties (still opt-in per case). */
  allowOnlineLookups: boolean;
  /** Allow DKIM key lookups over DNS when a case enables online lookups. */
  allowDkimDns: boolean;
  intel: IntelConfig;
  logLevel: 'fatal' | 'error' | 'warn' | 'info' | 'debug';
}

function num(name: string, def: number, min: number, max: number): number {
  const raw = process.env[name];
  if (raw === undefined || raw === '') return def;
  const v = Number(raw);
  if (!Number.isFinite(v) || v < min || v > max) throw new Error(`${name} must be a number between ${min} and ${max} (got "${raw}")`);
  return v;
}

function bool(name: string, def: boolean): boolean {
  const raw = process.env[name];
  if (raw === undefined || raw === '') return def;
  if (/^(1|true|yes|on)$/i.test(raw)) return true;
  if (/^(0|false|no|off)$/i.test(raw)) return false;
  throw new Error(`${name} must be true or false (got "${raw}")`);
}

function str(name: string): string | null {
  const v = process.env[name];
  return v && v.trim() ? v.trim() : null;
}

export function loadConfig(overrides: Partial<Config> = {}): Config {
  const dataDir = resolve(str('MAILSHARK_DATA_DIR') ?? 'data');
  const cert = str('MAILSHARK_TLS_CERT');
  const key = str('MAILSHARK_TLS_KEY');
  if (!!cert !== !!key) throw new Error('MAILSHARK_TLS_CERT and MAILSHARK_TLS_KEY must be set together');
  const misp = str('MISP_URL');
  if (misp && !/^https?:\/\//i.test(misp)) throw new Error('MISP_URL must be an http(s) URL');
  const since = str('MAILSHARK_MISP_FEED_SINCE') ?? '2019-01-01';
  if (!/^\d{4}-\d{2}-\d{2}$/.test(since)) throw new Error('MAILSHARK_MISP_FEED_SINCE must be YYYY-MM-DD');
  const level = (str('MAILSHARK_LOG_LEVEL') ?? 'info').toLowerCase();
  if (!['fatal', 'error', 'warn', 'info', 'debug'].includes(level)) throw new Error('MAILSHARK_LOG_LEVEL must be one of fatal, error, warn, info, debug');
  const cpus = Math.max(1, availableParallelism() - 1);

  const cfg: Config = {
    dataDir,
    host: str('MAILSHARK_HOST') ?? '127.0.0.1',
    port: num('MAILSHARK_PORT', 7380, 1, 65535),
    tls: cert && key ? { certPath: resolve(cert), keyPath: resolve(key) } : null,
    cookieSecure: bool('MAILSHARK_COOKIE_SECURE', !!(cert && key)),
    limits: {
      // The 100-file batch limit is a product requirement; it can be lowered, never raised.
      filesPerBatch: num('MAILSHARK_MAX_FILES', 100, 1, 100),
      fileBytes: num('MAILSHARK_MAX_FILE_MB', 50, 1, 2048) * 1024 * 1024,
      batchBytes: num('MAILSHARK_MAX_BATCH_MB', 1024, 1, 20480) * 1024 * 1024,
      messagesPerContainer: num('MAILSHARK_MAX_MBOX_MESSAGES', 10_000, 1, 1_000_000),
      rawViewBytes: 2 * 1024 * 1024,
    },
    workers: num('MAILSHARK_WORKERS', Math.min(cpus, 8), 1, 64),
    analysisTimeoutMs: num('MAILSHARK_ANALYSIS_TIMEOUT_S', 120, 5, 3600) * 1000,
    expandTimeoutMs: num('MAILSHARK_EXPAND_TIMEOUT_S', 600, 5, 7200) * 1000,
    correlateTimeoutMs: num('MAILSHARK_CORRELATE_TIMEOUT_S', 900, 10, 7200) * 1000,
    workerHeapMb: num('MAILSHARK_WORKER_HEAP_MB', 1024, 128, 16384),
    session: { idleMinutes: num('MAILSHARK_SESSION_IDLE_MIN', 480, 5, 10080), maxHours: num('MAILSHARK_SESSION_MAX_H', 24, 1, 720) },
    thresholds: {
      caution: num('MAILSHARK_CAUTION_AT', 35, 1, 99),
      danger: num('MAILSHARK_DANGER_AT', 70, 1, 99),
      coverageFloor: num('MAILSHARK_COVERAGE_FLOOR', 0.5, 0, 1),
    },
    allowOnlineLookups: bool('MAILSHARK_ALLOW_ONLINE_LOOKUPS', true),
    allowDkimDns: bool('MAILSHARK_ALLOW_DKIM_DNS', true),
    intel: {
      autoSync: bool('MAILSHARK_INTEL_AUTOSYNC', true),
      otxApiKey: str('OTX_API_KEY'),
      virusTotalApiKey: str('VT_API_KEY'),
      mispUrl: misp ? misp.replace(/\/+$/, '') : null,
      mispApiKey: str('MISP_API_KEY'),
      mispVerifyTls: bool('MISP_VERIFY_TLS', true),
      abusechAuthKey: str('ABUSECH_AUTH_KEY'),
      phishtankAppKey: str('PHISHTANK_APP_KEY'),
      bazaarFull: bool('MAILSHARK_BAZAAR_FULL', false),
      phishingDbLinks: bool('MAILSHARK_PHISHINGDB_LINKS', true),
      mispFeedSince: since,
      mispFeedBatch: num('MAILSHARK_MISP_FEED_BATCH', 400, 10, 100_000),
    },
    logLevel: level as Config['logLevel'],
    ...overrides,
  };
  if (cfg.thresholds.caution >= cfg.thresholds.danger) throw new Error('MAILSHARK_CAUTION_AT must be lower than MAILSHARK_DANGER_AT');
  for (const d of ['evidence', 'derived', 'reports', 'tmp']) mkdirSync(resolve(cfg.dataDir, d), { recursive: true });
  return cfg;
}

/** Non-secret configuration that influences analysis results; hashed into every result for reproducibility. */
export function analysisConfigFingerprint(cfg: Config): Record<string, unknown> {
  return { thresholds: cfg.thresholds, maxInspectBytes: 15_000_000, messagesPerContainer: cfg.limits.messagesPerContainer };
}
