// Evidence intake (batches of up to 100 files with per-file validation and upload progress),
// batch history, the evidence register and per-file chain of custody.
import { useRef, useState } from 'preact/hooks';
import { Download, FileUp, ShieldCheck, Trash2, UploadCloud, X } from 'lucide-preact';
import { api, ApiError, uploadFiles, type UploadHandle } from '../lib/api';
import { useApi } from '../lib/hooks';
import { href, navigate, setQuery, useRoute } from '../lib/router';
import { session } from '../lib/session';
import { toast, toastError, useStore } from '../lib/store';
import { fmtBytes, fmtNum, human, plural, short } from '../lib/format';
import type { BatchResult, BatchRow, EvidenceDetail, EvidenceRow } from '../lib/types';
import { useCase } from '../components/Shell';
import { Badge, ClassBadge, Drawer, Empty, ErrorBox, KV, Link, Loading, Mono, Notice, Panel, Time } from '../components/ui';
import { ProgressPanel } from './Overview';

interface Staged {
  file: File;
  problem: string | null;
  /** Oversized files are not sent at all (they would only be discarded by the server). */
  skip: boolean;
}

const EVIDENCE_STATUS: Record<string, string> = { stored: 'queued', expanding: 'running', expanded: 'ok', duplicate: 'inconclusive', rejected: 'failed', failed: 'failed' };

function Uploader({ onDone }: { onDone: () => void }) {
  const { c, reload } = useCase();
  const s = useStore(session);
  const limits = s.platform?.limits ?? { filesPerBatch: 100, fileBytes: 50 * 1048576, batchBytes: 1024 * 1048576, messagesPerContainer: 10000 };
  const [staged, setStaged] = useState<Staged[]>([]);
  const [note, setNote] = useState('');
  const [over, setOver] = useState(false);
  const [progress, setProgress] = useState<{ loaded: number; total: number } | null>(null);
  const [result, setResult] = useState<BatchResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const handle = useRef<UploadHandle<BatchResult> | null>(null);
  const input = useRef<HTMLInputElement>(null);

  const add = (files: FileList | File[]): void => {
    setResult(null);
    setError(null);
    const next = [...staged];
    for (const f of Array.from(files)) {
      if (next.some((x) => x.file.name === f.name && x.file.size === f.size && x.file.lastModified === f.lastModified)) continue;
      next.push({ file: f, problem: f.size === 0 ? 'Empty file: will be recorded as rejected' : f.size > limits.fileBytes ? `Larger than ${fmtBytes(limits.fileBytes)}: will not be sent` : null, skip: f.size > limits.fileBytes });
    }
    setStaged(next);
  };
  const sending = staged.filter((x) => !x.skip);
  const total = sending.reduce((n, x) => n + x.file.size, 0);
  const tooMany = sending.length > limits.filesPerBatch;
  const tooBig = total > limits.batchBytes;
  const uploading = progress !== null;

  const start = async (): Promise<void> => {
    setError(null);
    setResult(null);
    setProgress({ loaded: 0, total: 1 });
    // Empty files are still sent so the server records their rejection in the batch log; oversized
    // files are held back (the server would discard their bytes anyway) and stay listed here.
    const h = uploadFiles<BatchResult>(`/api/cases/${c.id}/batches`, sending.map((x) => x.file), note.trim() ? { note: note.trim() } : {}, (loaded, t) => setProgress({ loaded, total: t }));
    handle.current = h;
    try {
      const r = await h.promise;
      setResult(r);
      setStaged(staged.filter((x) => x.skip));
      setNote('');
      toast(`Batch received: ${r.accepted} accepted, ${r.rejected} rejected, ${r.duplicates} duplicate.`, r.rejected ? 'info' : 'success');
      reload();
      onDone();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : String(e));
    } finally {
      setProgress(null);
      handle.current = null;
    }
  };

  return (
    <Panel title="Add evidence" icon={<UploadCloud size={15} />}>
      <div class="col" style={{ gap: 'var(--sp-3)' }}>
        <div
          class="dropzone"
          data-over={over ? '' : undefined}
          role="button"
          tabIndex={0}
          onClick={() => !uploading && input.current?.click()}
          onKeyDown={(e) => (e.key === 'Enter' || e.key === ' ') && input.current?.click()}
          onDragOver={(e) => {
            e.preventDefault();
            setOver(true);
          }}
          onDragLeave={() => setOver(false)}
          onDrop={(e) => {
            e.preventDefault();
            setOver(false);
            if (!uploading && e.dataTransfer?.files) add(e.dataTransfer.files);
          }}
        >
          <FileUp />
          <h3>Drop email evidence here, or click to choose files</h3>
          <div class="small muted">
            .eml · .emlx · .mbox · Outlook .msg, detected by content, not by extension. Up to {limits.filesPerBatch} files per batch, {fmtBytes(limits.fileBytes)} per file, {fmtBytes(limits.batchBytes)} per batch.
          </div>
          <input
            ref={input}
            type="file"
            multiple
            hidden
            onChange={(e) => {
              const f = (e.target as HTMLInputElement).files;
              if (f) add(f);
              (e.target as HTMLInputElement).value = '';
            }}
          />
        </div>
        {staged.length > 0 && (
          <>
            <div class="row wrap">
              <b>{plural(staged.length, 'file')}</b>
              <span class="muted small">{fmtBytes(total)} to upload</span>
              <span class="spacer" />
              <button class="btn btn-sm btn-ghost" disabled={uploading} onClick={() => setStaged([])}>
                <Trash2 /> Clear
              </button>
            </div>
            {tooMany && <Notice c="danger">A batch can contain at most {limits.filesPerBatch} files; remove {sending.length - limits.filesPerBatch} or split them into several batches. The server rejects larger batches as a whole.</Notice>}
            {tooBig && <Notice c="danger">The batch exceeds {fmtBytes(limits.batchBytes)}. Split it into smaller batches.</Notice>}
            <div class="table-wrap staged">
              <table class="t compact">
                <thead>
                  <tr>
                    <th>File</th>
                    <th class="num" style={{ width: '90px' }}>
                      Size
                    </th>
                    <th style={{ width: '200px' }}>Check</th>
                    <th style={{ width: '36px' }} />
                  </tr>
                </thead>
                <tbody>
                  {staged.map((x, i) => (
                    <tr data-c={x.problem ? 'failed' : undefined}>
                      <td title={x.file.name}>{x.file.name}</td>
                      <td class="num">{fmtBytes(x.file.size)}</td>
                      <td>{x.problem ? <span style={{ color: 'var(--failed)' }}>{x.problem}</span> : <span class="faint">ready</span>}</td>
                      <td>
                        <button class="btn btn-ghost btn-sm btn-icon" disabled={uploading} aria-label={`Remove ${x.file.name}`} onClick={() => setStaged(staged.filter((_, j) => j !== i))}>
                          <X />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <input class="input" placeholder="Batch note (optional): source, collection method, ticket…" value={note} maxLength={2000} disabled={uploading} onInput={(e) => setNote((e.target as HTMLInputElement).value)} />
            {progress ? (
              <div class="col" style={{ gap: '6px' }}>
                <div class="bar">
                  <span data-c="accent" style={{ width: `${Math.round((progress.loaded / Math.max(1, progress.total)) * 100)}%` }} />
                </div>
                <div class="row small muted">
                  <span>
                    Uploading {fmtBytes(progress.loaded)} / {fmtBytes(progress.total)}
                    {progress.loaded >= progress.total ? ' (server is hashing and storing the files…)' : ''}
                  </span>
                  <span class="spacer" />
                  <button class="btn btn-sm" onClick={() => handle.current?.abort()}>
                    Cancel
                  </button>
                </div>
              </div>
            ) : (
              <div class="row">
                <span class="small faint grow">Originals are stored unchanged (content-addressed by SHA-256) before any parsing.</span>
                <button class="btn btn-primary" disabled={tooMany || tooBig || sending.length === 0} onClick={() => void start()}>
                  <UploadCloud /> Upload {plural(sending.length, 'file')}
                </button>
              </div>
            )}
          </>
        )}
        {error && <Notice c="danger">{error}</Notice>}
        {result && <BatchOutcome r={result} />}
      </div>
    </Panel>
  );
}

function BatchOutcome({ r }: { r: BatchResult }) {
  const problems = r.evidence.filter((e) => e.status !== 'stored');
  return (
    <div class="col" style={{ gap: '8px' }}>
      <Notice c={r.rejected ? 'warn' : 'info'}>
        Batch <span class="mono">{short(r.batchId, 18)}</span>: <b>{r.accepted}</b> accepted for analysis, <b>{r.rejected}</b> rejected, <b>{r.duplicates}</b> duplicate (identical SHA-256 already in this case, linked to the first copy).
      </Notice>
      {problems.length > 0 && (
        <table class="t compact">
          <tbody>
            {problems.map((e) => (
              <tr data-c={e.status === 'rejected' ? 'failed' : undefined}>
                <td class="trunc" title={e.originalName}>
                  {e.originalName}
                </td>
                <td style={{ width: '100px' }}>
                  <Badge c={EVIDENCE_STATUS[e.status]}>{e.status}</Badge>
                </td>
                <td class="wrap small">{e.error ? `${e.error.message} (${e.error.code})` : e.duplicateOf ? 'Same content as an earlier upload.' : ''}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

function EvidenceDrawer({ id, onClose }: { id: string; onClose: () => void }) {
  const { c } = useCase();
  const d = useApi<EvidenceDetail>(`/api/cases/${c.id}/evidence/${id}`, undefined, { keep: false });
  const [verify, setVerify] = useState<{ ok: boolean; expected?: string; actual?: string; reason?: string; checkedAt?: number } | null>(null);
  const [busy, setBusy] = useState(false);
  const e = d.data?.evidence;
  const runVerify = async (): Promise<void> => {
    setBusy(true);
    try {
      setVerify(await api.post(`/api/cases/${c.id}/evidence/${id}/verify`));
    } catch (err) {
      toastError(err);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Drawer
      title={e ? String(e.original_name) : 'Evidence'}
      sub="Original evidence file · chain of custody"
      onClose={onClose}
      actions={
        e && e.sha256 !== '-' ? (
          <>
            <button class="btn btn-sm" disabled={busy} onClick={() => void runVerify()} title="Re-hash the stored bytes and compare with the SHA-256 recorded at intake">
              <ShieldCheck /> Verify integrity
            </button>
            <a class="btn btn-sm" href={`/api/cases/${c.id}/evidence/${id}/download`} download title="Download the original bytes (verified before serving; audit-logged)">
              <Download /> Original
            </a>
          </>
        ) : null
      }
    >
      <ErrorBox error={d.error} retry={d.reload} />
      {!e ? (
        <Loading />
      ) : (
        <>
          {verify && (
            <Notice c={verify.ok ? 'info' : 'danger'}>
              {verify.reason ??
                (verify.ok
                  ? `Stored bytes match the intake SHA-256 (checked ${new Date(verify.checkedAt ?? Date.now()).toISOString()}). This shows the copy held by the platform is unchanged since intake; it says nothing about how the file was collected.`
                  : `MISMATCH: stored bytes hash to ${verify.actual}, intake recorded ${verify.expected}. Treat this copy as compromised; the event is in the audit log.`)}
            </Notice>
          )}
          <KV
            rows={[
              ['Status', <Badge c={EVIDENCE_STATUS[e.status]}>{e.status}</Badge>],
              ['Detected format', e.format ?? '—'],
              ['Declared type', String(e['declared_type'] ?? '—')],
              ['Size', `${fmtBytes(e.size)} (${fmtNum(e.size)} bytes)`],
              ['SHA-256', <Mono value={e.sha256} />],
              ['SHA-1', <Mono value={e.sha1} />],
              ['MD5', <Mono value={e.md5} />],
              ['Received', <Time ms={e.received_at} />],
              ['Batch', <span class="mono">{String(e['batch_id'])}</span>],
              ['Messages', e['message_count'] === null ? '—' : fmtNum(Number(e['message_count'])) + (e['truncated'] ? ' (container truncated at the configured limit)' : '')],
              ...(e['error_code'] ? ([['Error', `${String(e['error_detail'] ?? '')} (${String(e['error_code'])})`]] as [string, string][]) : []),
            ]}
          />
          <div>
            <div class="section-title">Chain of custody (processing history)</div>
            <ul class="timeline">
              {d.data!.history.map((h) => (
                <li>
                  <span class="when">
                    <Time ms={h.ts} />
                  </span>
                  <span>
                    <b>{human(h.kind)}</b>
                    {h.detail && <div class="mono xs faint break">{h.detail}</div>}
                  </span>
                </li>
              ))}
            </ul>
          </div>
          <div>
            <div class="section-title">Messages extracted ({d.data!.messages.length})</div>
            {d.data!.messages.length === 0 ? (
              <span class="small faint">None (yet).</span>
            ) : (
              <table class="t compact">
                <thead>
                  <tr>
                    <th style={{ width: '50px' }}>#</th>
                    <th>Subject</th>
                    <th style={{ width: '110px' }}>Class</th>
                    <th style={{ width: '120px' }}>Derivation</th>
                  </tr>
                </thead>
                <tbody>
                  {d.data!.messages.map((m) => (
                    <tr class="clickable" onClick={() => navigate(href(`/cases/${c.id}/messages`, { evidence: id, m: m.id }))}>
                      <td class="num">{m.containerIndex}</td>
                      <td title={m.subject ?? ''}>{m.subject ?? <span class="faint">{m.status}</span>}</td>
                      <td>{m.status === 'analyzed' || m.status === 'failed' ? <ClassBadge c={m.class} /> : <Badge c={m.status === 'duplicate' ? 'inconclusive' : 'pending'}>{m.status}</Badge>}</td>
                      <td class="small muted" title={m.byteOffset !== null ? `byte offset ${m.byteOffset}` : undefined}>
                        {m.derivation}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </>
      )}
    </Drawer>
  );
}

export function Evidence() {
  const { c } = useCase();
  const s = useStore(session);
  const { query } = useRoute();
  const batch = query.get('batch');
  const selected = query.get('e');
  const ev = useApi<EvidenceRow[]>(`/api/cases/${c.id}/evidence`, { batch }, { poll: c.counts.pending > 0 ? 2500 : 20_000 });
  const batches = useApi<BatchRow[]>(`/api/cases/${c.id}/batches`, undefined, { poll: c.counts.pending > 0 ? 2500 : 20_000 });
  const canUpload = c.myRole !== 'viewer' && c.status === 'open' && s.user?.role !== 'viewer';
  const rows = ev.data ?? [];
  return (
    <div class="page">
      <div class="page-head">
        <div>
          <div class="eyebrow">Original evidence</div>
          <h1>Evidence</h1>
        </div>
      </div>
      <div class="grid grid-main" style={{ marginBottom: 'var(--sp-3)' }}>
        <div class="col" style={{ gap: 'var(--sp-3)' }}>
          {canUpload ? (
            <Uploader
              onDone={() => {
                ev.reload();
                batches.reload();
              }}
            />
          ) : (
            <Notice>{c.status !== 'open' ? `The case is ${c.status}; evidence can only be added to open cases.` : 'Your role in this case is read-only.'}</Notice>
          )}
        </div>
        <div class="col" style={{ gap: 'var(--sp-3)' }}>
          <ProgressPanel caseId={c.id} />
          <Panel title="Batches" tight>
            {!batches.data ? (
              <Loading />
            ) : batches.data.length === 0 ? (
              <Empty title="No batches yet" />
            ) : (
              <div style={{ maxHeight: '320px', overflow: 'auto' }}>
                {batches.data.map((b) => {
                  const done = b.messages - b.pending;
                  return (
                    <div class="batch-card">
                      <div class="col" style={{ gap: '2px', minWidth: 0 }}>
                        <span class="small">
                          <Time ms={b.createdAt} /> · {b.createdBy}
                        </span>
                        <span class="small muted trunc">
                          {plural(b.fileCount, 'file')} ({b.acceptedCount} accepted) · {fmtBytes(b.totalBytes)} · {plural(b.messages, 'message')}
                          {b.failed ? ` · ${b.failed} failed` : ''}
                          {b.note ? ` · “${b.note}”` : ''}
                        </span>
                      </div>
                      <div class="row">
                        <Link class="btn btn-sm" href={href(`/cases/${c.id}/messages`, { batch: b.id })}>
                          Messages
                        </Link>
                        <button class="btn btn-sm btn-ghost" aria-pressed={batch === b.id} onClick={() => setQuery({ batch: batch === b.id ? null : b.id })}>
                          {batch === b.id ? 'All files' : 'Files'}
                        </button>
                      </div>
                      {b.pending > 0 && (
                        <div class="bar">
                          <span data-c="accent" style={{ width: `${(done / Math.max(1, b.messages)) * 100}%` }} />
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </Panel>
        </div>
      </div>
      <Panel title={batch ? 'Evidence register (one batch)' : 'Evidence register'} actions={<span class="small muted">{plural(rows.length, 'file')}</span>} tight>
        <ErrorBox error={ev.error} retry={ev.reload} />
        {!ev.data ? (
          <Loading />
        ) : rows.length === 0 ? (
          <Empty title="No evidence files" />
        ) : (
          <div class="table-wrap" style={{ maxHeight: '60vh' }}>
            <table class="t">
              <thead>
                <tr>
                  <th>File name</th>
                  <th style={{ width: '70px' }}>Format</th>
                  <th class="num" style={{ width: '80px' }}>
                    Size
                  </th>
                  <th style={{ width: '170px' }}>SHA-256</th>
                  <th style={{ width: '170px' }}>Received</th>
                  <th style={{ width: '100px' }}>Status</th>
                  <th class="num" style={{ width: '80px' }}>
                    Messages
                  </th>
                  <th style={{ width: '190px' }}>Analysis</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((e) => (
                  <tr class="clickable" aria-selected={selected === e.id} data-c={e.status === 'rejected' || e.status === 'failed' ? 'failed' : undefined} onClick={() => setQuery({ e: e.id }, { replace: false })}>
                    <td title={e.originalName}>{e.originalName}</td>
                    <td class="muted">{e.format ?? '—'}</td>
                    <td class="num">{fmtBytes(e.size)}</td>
                    <td class="mono" title={e.sha256}>
                      {e.sha256 === '-' ? '—' : short(e.sha256, 16)}
                    </td>
                    <td>
                      <Time ms={e.receivedAt} />
                    </td>
                    <td title={e.errorDetail ?? undefined}>
                      <Badge c={EVIDENCE_STATUS[e.status]}>{e.status}</Badge>
                    </td>
                    <td class="num">{e.messageCount ?? '—'}</td>
                    <td class="small">
                      {e.errorDetail ? (
                        <span style={{ color: 'var(--failed)' }} title={e.errorDetail}>
                          {e.errorDetail}
                        </span>
                      ) : e.status === 'duplicate' ? (
                        <span class="faint">identical to an earlier file</span>
                      ) : (
                        <span class="muted">
                          {e.analyzed} done{e.pending ? ` · ${e.pending} pending` : ''}
                          {e.failed ? ` · ${e.failed} failed` : ''}
                        </span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
      {selected && <EvidenceDrawer id={selected} onClose={() => setQuery({ e: null })} />}
    </div>
  );
}
