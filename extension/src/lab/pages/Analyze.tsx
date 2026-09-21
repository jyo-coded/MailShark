// Offline analysis of saved messages: .eml files (Thunderbird, Apple Mail, Outlook "Save as") and
// .mbox archives (Google Takeout, Thunderbird). Files are read locally and never uploaded.
import { useRef, useState } from 'preact/hooks';
import { send, type ReportSummary } from '../../shared/protocol';
import { formatBytes, plural } from '../../shared/format';
import { Chip } from '../../ui/primitives';
import { SharkMark, Scanner } from '../../ui/SharkMark';
import { FileText, GitFork, Lock, Upload, X } from '../../ui/icons';
import { MailRow, PageHead } from '../components';
import { go, type LabContext } from '../nav';

const MAX_FILE = 300 * 1024 * 1024;
const MAX_MESSAGES = 5000;

async function readLatin1(file: File): Promise<string> {
  const buf = new Uint8Array(await file.arrayBuffer());
  let out = '';
  const CHUNK = 0x8000;
  for (let i = 0; i < buf.length; i += CHUNK) out += String.fromCharCode.apply(null, Array.from(buf.subarray(i, i + CHUNK)));
  return out;
}

/** Split an mbox (mboxo/mboxrd) into raw messages. */
export function splitMbox(text: string): string[] {
  const out: string[] = [];
  const lines = text.split(/\r?\n/);
  let cur: string[] | null = null;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i] as string;
    if (line.startsWith('From ') && (i === 0 || (lines[i - 1] ?? '') === '')) {
      if (cur && cur.length) out.push(cur.join('\r\n'));
      cur = [];
      continue;
    }
    if (cur) cur.push(/^>+From /.test(line) ? line.slice(1) : line);
  }
  if (cur && cur.length) out.push(cur.join('\r\n'));
  return out.filter((m) => /^[A-Za-z-]+:/m.test(m.slice(0, 2000)));
}

interface Job {
  name: string;
  size: number;
  messages: string[];
}

export function AnalyzePage({ ctx }: { ctx: LabContext }) {
  const [over, setOver] = useState(false);
  const [busy, setBusy] = useState<{ done: number; total: number; file: string } | null>(null);
  const [results, setResults] = useState<ReportSummary[]>([]);
  const [errors, setErrors] = useState<string[]>([]);
  const cancel = useRef(false);
  const input = useRef<HTMLInputElement>(null);

  const run = async (files: File[]): Promise<void> => {
    cancel.current = false;
    setErrors([]);
    const jobs: Job[] = [];
    const errs: string[] = [];
    for (const f of files) {
      const lower = f.name.toLowerCase();
      if (f.size > MAX_FILE) {
        errs.push(`${f.name}: larger than ${formatBytes(MAX_FILE)}`);
        continue;
      }
      if (lower.endsWith('.msg')) {
        errs.push(`${f.name}: Outlook .msg isn’t supported. Use File → Save As → .eml in Outlook instead.`);
        continue;
      }
      const text = await readLatin1(f);
      const isMbox = lower.endsWith('.mbox') || lower.endsWith('.mbx') || /^From \S+/.test(text.slice(0, 200));
      const messages = isMbox ? splitMbox(text) : [text];
      if (!messages.length || !/^[A-Za-z-]+:/m.test((messages[0] ?? '').slice(0, 4000))) {
        errs.push(`${f.name}: doesn’t look like an email (.eml) or mailbox (.mbox) file`);
        continue;
      }
      jobs.push({ name: f.name, size: f.size, messages: messages.slice(0, MAX_MESSAGES) });
    }
    setErrors(errs);
    const total = jobs.reduce((n, j) => n + j.messages.length, 0);
    if (!total) return;
    let done = 0;
    setBusy({ done, total, file: jobs[0]?.name ?? '' });
    const out: ReportSummary[] = [];
    for (const job of jobs) {
      for (const raw of job.messages) {
        if (cancel.current) break;
        const res = await send({ kind: 'analyze', raw, meta: { source: 'file', messageId: null, threadId: null, fileName: job.name } });
        done++;
        if (res.ok) out.push(res.summary);
        else errs.push(`${job.name}: ${res.error}`);
        if (done % 5 === 0 || done === total) {
          setBusy({ done, total, file: job.name });
          setResults([...out].sort((a, b) => b.score - a.score));
        }
      }
    }
    setResults([...out].sort((a, b) => b.score - a.score));
    setErrors(errs);
    setBusy(null);
    ctx.refreshStats();
  };

  const counts = { danger: results.filter((r) => r.verdict === 'danger').length, caution: results.filter((r) => r.verdict === 'caution').length };
  const campaigns = new Set(results.filter((r) => r.campaign && r.campaign.size > 1).map((r) => r.campaign!.id)).size;

  return (
    <>
      <PageHead eyebrow="Offline forensics" title="Analyze files">
        Drop saved emails (.eml) or whole mailboxes (.mbox from Google Takeout or Thunderbird). MailShark dissects every message and traces campaigns across them, entirely on this device.
      </PageHead>

      <div
        class="ms-drop"
        data-over={over ? '' : undefined}
        onDragOver={(e) => {
          e.preventDefault();
          setOver(true);
        }}
        onDragLeave={() => setOver(false)}
        onDrop={(e) => {
          e.preventDefault();
          setOver(false);
          const files = [...(e.dataTransfer?.files ?? [])];
          if (files.length && !busy) void run(files);
        }}
      >
        {busy ? (
          <>
            <SharkMark size={64} state="scan" />
            <div class="ms-h3">
              Dissecting {busy.done.toLocaleString()} of {plural(busy.total, 'message')}…
            </div>
            <div style={{ color: 'var(--ms-accent)' }}>
              <Scanner width={320} />
            </div>
            <div class="ms-meter" style={{ width: '320px' }}>
              <span style={{ width: `${(busy.done / busy.total) * 100}%` }} />
            </div>
            <span class="ms-faint" style={{ fontSize: '12px' }}>{busy.file}</span>
            <button type="button" class="ms-btn ms-btn--sm" onClick={() => (cancel.current = true)}>
              <X /> Stop
            </button>
          </>
        ) : (
          <>
            <SharkMark size={64} state="idle" />
            <div class="ms-h2">Drop .eml or .mbox files here</div>
            <div class="ms-muted">or</div>
            <button type="button" class="ms-btn ms-btn--primary ms-btn--lg" onClick={() => input.current?.click()}>
              <Upload /> Choose files
            </button>
            <input
              ref={input}
              type="file"
              multiple
              accept=".eml,.mbox,.mbx,.txt,message/rfc822,application/mbox"
              style={{ display: 'none' }}
              onChange={(e) => {
                const files = [...((e.target as HTMLInputElement).files ?? [])];
                (e.target as HTMLInputElement).value = '';
                if (files.length) void run(files);
              }}
            />
            <div class="ms-row ms-faint" style={{ fontSize: '12px', gap: '6px' }}>
              <Lock size={13} /> Files are read in memory and never leave your browser.
            </div>
          </>
        )}
      </div>

      {errors.length > 0 && (
        <div class="ms-card ms-card--pad" style={{ marginTop: '14px', borderColor: 'var(--ms-caution-line)' }}>
          {errors.slice(0, 8).map((e) => (
            <div class="ms-muted" style={{ fontSize: '12.5px' }}>
              {e}
            </div>
          ))}
          {errors.length > 8 && <div class="ms-faint">…and {errors.length - 8} more</div>}
        </div>
      )}

      {results.length > 0 && (
        <div class="ms-panel" style={{ marginTop: '18px' }}>
          <div class="ms-panel-head">
            <span class="ms-h3">Results</span>
            <div class="ms-row">
              <Chip icon={<FileText />}>{plural(results.length, 'message')}</Chip>
              {counts.danger > 0 && <Chip tone="danger">{counts.danger} phishing</Chip>}
              {counts.caution > 0 && <Chip tone="caution">{counts.caution} suspicious</Chip>}
              {campaigns > 0 && (
                <button type="button" class="ms-chip ms-chip--accent" style={{ cursor: 'pointer' }} onClick={() => go('campaigns')}>
                  <GitFork /> {plural(campaigns, 'campaign')}
                </button>
              )}
            </div>
          </div>
          <div class="ms-list">
            {results.slice(0, 200).map((s) => (
              <MailRow s={s} onOpen={ctx.openReport} />
            ))}
          </div>
        </div>
      )}
    </>
  );
}
