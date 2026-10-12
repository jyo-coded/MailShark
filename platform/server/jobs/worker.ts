// Analysis worker thread. Runs CPU-heavy, untrusted-input work away from the API thread:
//   expand     container file → message artifacts (stored as derived blobs when not identical)
//   analyze    message artifact → engine report (+ intel provider over intel.db, optional DKIM DNS)
//   correlate  case → relationship edges, clusters, external intelligence matches
// The parent enforces timeouts and heap limits; a crash or hang here only kills this worker.
import { Resolver } from 'node:dns/promises';
import { parentPort } from 'node:worker_threads';
import { analyzeEmail } from '../../../engine/src/analyze';
import type { DkimKeyResolver, Fingerprint, IntelProvider, Report } from '../../../engine/src/types';
import { BlobStore, type BlobKind } from '../evidence/store';
import { detectFormat, expand, type EvidenceFormat } from '../evidence/formats';
import { IntelStore } from '../intel/store';
import { Db } from '../db/sqlite';
import { correlate, type CorrConfig, type CorrMessage, type CorrObservation } from '../correlation/engine';
import { externalMatches } from '../correlation/external';

export type WorkerTask =
  | { kind: 'expand'; dataDir: string; evidenceSha256: string; maxMessages: number }
  | {
      kind: 'analyze';
      dataDir: string;
      blobStore: BlobKind;
      blobSha256: string;
      derivation: string;
      intelDbPath: string | null;
      dkimDns: boolean;
      thresholds: { caution: number; danger: number; coverageFloor: number };
    }
  | { kind: 'correlate'; caseDbPath: string; intelDbPath: string | null; caseId: string; config: Partial<CorrConfig> };

export interface ExpandOutput {
  format: EvidenceFormat;
  formatNote: string;
  truncated: boolean;
  notes: string[];
  messages: { index: number; offset: number | null; size: number; sha256: string; blobStore: BlobKind; derivation: string; notes: string[] }[];
}

export interface AnalyzeOutput {
  report: Report;
  durationMs: number;
  intelSnapshot: string | null;
  notes: string[];
}

let intelStore: IntelStore | null = null;
let intelPath: string | null = null;

function intel(path: string | null): IntelStore | null {
  if (!path) return null;
  if (intelStore && intelPath === path) return intelStore;
  try {
    intelStore = new IntelStore(path, { readOnly: true });
    intelPath = path;
  } catch {
    intelStore = null;
  }
  return intelStore;
}

/** Engine-facing view of intel.db: indicator listings plus actionable (to_ids) event indicators. */
function intelProvider(store: IntelStore): IntelProvider {
  const sources = (hits: { source: string; suppressed: string | null; threat?: string | null }[]): string | null => {
    const names = [...new Set(hits.filter((h) => !h.suppressed && h.threat !== 'tor-exit').map((h) => h.source))];
    return names.length ? names.join(', ') : null;
  };
  return {
    lookupDomain(domain: string): string | null {
      const listed = sources(store.lookupHost(domain));
      if (listed) return listed;
      return sources(store.lookupEvents('domain', domain).filter((e) => e.toIds && e.matchType === 'host'));
    },
    lookupUrl(url: string): string | null {
      const listed = sources(store.lookupUrl(url));
      if (listed) return listed;
      return sources(store.lookupEvents('url', url).filter((e) => e.toIds));
    },
  };
}

const dnsResolver = new Resolver({ timeout: 4000, tries: 2 });
const resolveDkim: DkimKeyResolver = async (selector, domain) => {
  if (!/^[a-z0-9._-]{1,200}$/i.test(selector) || !/^[a-z0-9.-]{1,253}$/i.test(domain)) return null;
  try {
    const recs = await dnsResolver.resolveTxt(`${selector}._domainkey.${domain}`);
    const joined = recs.map((r) => r.join(''));
    return joined.find((r) => /(^|;)\s*p=/i.test(r)) ?? joined[0] ?? null;
  } catch (e) {
    const code = (e as { code?: string }).code;
    if (code === 'ENOTFOUND' || code === 'ENODATA' || code === 'NXDOMAIN') return null;
    throw e;
  }
};

async function runExpand(t: Extract<WorkerTask, { kind: 'expand' }>): Promise<ExpandOutput> {
  const store = new BlobStore(t.dataDir);
  const bytes = await store.read('evidence', t.evidenceSha256, true);
  const det = detectFormat(bytes.subarray(0, 65536));
  const exp = expand(new Uint8Array(bytes.buffer, bytes.byteOffset, bytes.byteLength), det.format, t.maxMessages);
  const messages: ExpandOutput['messages'] = [];
  for (const m of exp.messages) {
    if (m.derivation === 'original') {
      messages.push({ index: m.index, offset: m.offset, size: m.bytes.length, sha256: t.evidenceSha256, blobStore: 'evidence', derivation: m.derivation, notes: m.notes });
    } else {
      const put = await store.putBytes('derived', m.bytes);
      messages.push({ index: m.index, offset: m.offset, size: m.bytes.length, sha256: put.sha256, blobStore: 'derived', derivation: m.derivation, notes: m.notes });
    }
  }
  return { format: det.format, formatNote: det.note, truncated: exp.truncated, notes: exp.notes, messages };
}

async function runAnalyze(t: Extract<WorkerTask, { kind: 'analyze' }>): Promise<AnalyzeOutput> {
  const store = new BlobStore(t.dataDir);
  const bytes = await store.read(t.blobStore, t.blobSha256, true);
  const is = intel(t.intelDbPath);
  const started = performance.now();
  const report = await analyzeEmail(new Uint8Array(bytes.buffer, bytes.byteOffset, bytes.byteLength), {
    intel: is ? intelProvider(is) : null,
    dkimKeyResolver: t.dkimDns ? resolveDkim : null,
    thresholds: t.thresholds,
  });
  const notes: string[] = [];
  if (t.derivation === 'reconstructed-from-msg') {
    // The MIME body was synthesised from Outlook properties: a DKIM body-hash mismatch is expected
    // and says nothing about the original message.
    report.findings = report.findings.filter((f) => !(f.id === 'dkim.body-modified' || f.id === 'dkim.modified-after-delivery'));
    for (const d of report.dkim ?? []) {
      if (d.bodyHash === 'fail') {
        d.bodyHash = 'not-checked';
        d.detail = 'Not checkable: the body was reconstructed from an Outlook .msg item.';
      }
    }
    notes.push('Message reconstructed from Outlook .msg: byte-level body checks were not applied.');
  }
  return { report, durationMs: Math.round((performance.now() - started) * 10) / 10, intelSnapshot: is ? is.snapshotId() : null, notes };
}

function runCorrelate(t: Extract<WorkerTask, { kind: 'correlate' }>): unknown {
  const db = new Db(t.caseDbPath, { readOnly: true });
  try {
    const rows = db.all<{ id: string; class: string | null; score: number | null; sent_at: number | null; subject: string | null; fingerprint_json: string }>(
      `SELECT m.id, m.class, m.score, m.sent_at, m.subject, r.fingerprint_json FROM messages m JOIN results r ON r.message_id = m.id
       WHERE m.case_id = ? AND m.status = 'analyzed'`,
      t.caseId,
    );
    const messages: CorrMessage[] = rows.map((r) => {
      const fp = JSON.parse(r.fingerprint_json) as Fingerprint;
      return { id: r.id, cls: r.class, score: r.score, time: fp.time || r.sent_at, fp };
    });
    const observations = db.all<CorrObservation>(
      `SELECT o.message_id AS messageId, i.type AS type, i.value AS value, o.role AS role, o.context AS context
       FROM observations o JOIN indicators i ON i.id = o.indicator_id
       JOIN messages m ON m.id = o.message_id
       WHERE o.case_id = ? AND m.status = 'analyzed'`,
      t.caseId,
    );
    const is = intel(t.intelDbPath);
    const env = {
      popularity: (d: string | null) => (is ? is.popularity(d) : null),
      asn: (ip: string) => (is ? is.asn(ip) : null),
    };
    const result = correlate(messages, observations, env, t.config);
    const external = is ? externalMatches(is, observations, new Map(rows.filter((r) => r.subject).map((r) => [r.id, r.subject as string]))) : { matches: [], campaigns: [] };
    return { ...result, external, intelSnapshot: is ? is.snapshotId() : null };
  } finally {
    db.close();
  }
}

parentPort?.on('message', (msg: { taskId: number; task: WorkerTask }) => {
  void (async () => {
    try {
      let result: unknown;
      if (msg.task.kind === 'expand') result = await runExpand(msg.task);
      else if (msg.task.kind === 'analyze') result = await runAnalyze(msg.task);
      else result = runCorrelate(msg.task);
      parentPort?.postMessage({ taskId: msg.taskId, ok: true, result });
    } catch (e) {
      const err = e as { code?: string; message?: string; name?: string };
      parentPort?.postMessage({ taskId: msg.taskId, ok: false, error: { code: err.code ?? err.name ?? 'error', message: err.message ?? String(e) } });
    }
  })();
});
