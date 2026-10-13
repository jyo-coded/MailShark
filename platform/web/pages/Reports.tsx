// Report generation (JSON by default, Markdown and DOCX rendered from the same data) and the
// register of generated reports with their hashes.
import { useState } from 'preact/hooks';
import { Download, FileJson, FileText, FileType } from 'lucide-preact';
import { api } from '../lib/api';
import { useApi } from '../lib/hooks';
import { useRoute } from '../lib/router';
import { toast, toastError } from '../lib/store';
import { fmtBytes, plural } from '../lib/format';
import type { BatchRow, ReportRow } from '../lib/types';
import { useCase } from '../components/Shell';
import { Badge, Empty, ErrorBox, Loading, Mono, Notice, Panel, Time } from '../components/ui';

const FORMATS = [
  { id: 'json', label: 'JSON', icon: <FileJson />, hint: 'Canonical, machine-readable, validated against the published schema. The other formats are rendered from this data.' },
  { id: 'md', label: 'Markdown', icon: <FileText />, hint: 'Readable text for tickets and wikis. Indicators are defanged.' },
  { id: 'docx', label: 'Word (DOCX)', icon: <FileType />, hint: 'Document for case files. Indicators are defanged.' },
] as const;

export function Reports() {
  const { c } = useCase();
  const { query } = useRoute();
  const highlight = query.get('r');
  const reports = useApi<ReportRow[]>(`/api/cases/${c.id}/reports`);
  const batches = useApi<BatchRow[]>(`/api/cases/${c.id}/batches`);
  const [formats, setFormats] = useState<Set<'json' | 'md' | 'docx'>>(new Set(['json']));
  const [scope, setScope] = useState<'case' | 'batch'>('case');
  const [batchId, setBatchId] = useState('');
  const [busy, setBusy] = useState(false);
  const generate = async (): Promise<void> => {
    setBusy(true);
    try {
      const r = await api.post<{ files: unknown[] }>(`/api/cases/${c.id}/reports`, { formats: FORMATS.map((f) => f.id).filter((f) => formats.has(f)), scope, ...(scope === 'batch' ? { batchId } : {}) });
      toast(`Report generated in ${r.files.length} format${r.files.length === 1 ? '' : 's'} from the same data.`, 'success');
      reports.reload();
    } catch (e) {
      toastError(e);
    } finally {
      setBusy(false);
    }
  };
  return (
    <div class="page">
      <div class="page-head">
        <div>
          <div class="eyebrow">Findings for others</div>
          <h1>Reports</h1>
        </div>
        <div class="actions">
          <a class="btn btn-sm" href="/api/schema/report" target="_blank" rel="noopener">
            JSON Schema
          </a>
        </div>
      </div>
      <div class="grid grid-main">
        <Panel title="Registry" tight>
          <ErrorBox error={reports.error} retry={reports.reload} />
          {!reports.data ? (
            <Loading />
          ) : reports.data.length === 0 ? (
            <Empty icon={<FileText />} title="No reports yet">
              Generate one on the right, or select messages in the workspace and choose Report.
            </Empty>
          ) : (
            <div class="table-wrap">
              <table class="t">
                <thead>
                  <tr>
                    <th style={{ width: '172px' }}>Generated</th>
                    <th style={{ width: '76px' }}>Format</th>
                    <th>Scope · report id</th>
                    <th style={{ width: '124px' }}>File SHA-256</th>
                    <th style={{ width: '124px' }}>Data SHA-256</th>
                    <th class="num" style={{ width: '70px' }}>
                      Size
                    </th>
                    <th style={{ width: '56px' }} />
                  </tr>
                </thead>
                <tbody>
                  {reports.data.map((r) => (
                    <tr aria-selected={highlight === r.id}>
                      <td>
                        <Time ms={r.createdAt} />
                        <div class="xs faint">{r.createdBy}</div>
                      </td>
                      <td>
                        <Badge outline>{r.format}</Badge>
                      </td>
                      <td class="small" title={r.reportId}>
                        {r.scope}
                        {r.scopeRef ? ` · ${r.scopeRef}` : ''}
                        <div class="mono xs faint trunc">{r.reportId}</div>
                      </td>
                      <td>
                        <Mono value={r.fileSha256} max={10} />
                      </td>
                      <td title="SHA-256 of the canonical report data. Renderings generated together (same report id) share it.">
                        <Mono value={r.dataSha256} max={10} />
                      </td>
                      <td class="num">{fmtBytes(r.size)}</td>
                      <td>
                        <a class="btn btn-sm btn-icon" href={`/api/cases/${c.id}/reports/${r.id}/download`} download aria-label="Download report" title="Download">
                          <Download />
                        </a>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Panel>
        <Panel title="Generate">
          <div class="col" style={{ gap: 'var(--sp-3)' }}>
            <div class="field">
              <span class="label">Formats</span>
              {FORMATS.map((f) => (
                <label class="check" title={f.hint}>
                  <input
                    type="checkbox"
                    checked={formats.has(f.id)}
                    onChange={(e) => {
                      const n = new Set(formats);
                      (e.target as HTMLInputElement).checked ? n.add(f.id) : n.delete(f.id);
                      setFormats(n);
                    }}
                  />
                  {f.label}
                  <span class="xs faint">{f.id === 'json' ? 'default' : ''}</span>
                </label>
              ))}
              <span class="hint">All selected formats are rendered from one report build and share its report id and data SHA-256. {FORMATS[0].hint}</span>
            </div>
            <div class="field">
              <span class="label">Scope</span>
              <label class="check">
                <input type="radio" name="scope" checked={scope === 'case'} onChange={() => setScope('case')} /> Whole case ({plural(c.counts.messages, 'message')})
              </label>
              <label class="check">
                <input type="radio" name="scope" checked={scope === 'batch'} onChange={() => setScope('batch')} disabled={!batches.data?.length} /> One batch
              </label>
              {scope === 'batch' && (
                <select class="select" value={batchId} onChange={(e) => setBatchId((e.target as HTMLSelectElement).value)}>
                  <option value="">Choose a batch…</option>
                  {(batches.data ?? []).map((b) => (
                    <option value={b.id}>
                      {new Date(b.createdAt).toISOString().slice(0, 16).replace('T', ' ')}Z · {b.fileCount} files{b.note ? ` · ${b.note.slice(0, 40)}` : ''}
                    </option>
                  ))}
                </select>
              )}
            </div>
            {c.counts.pending > 0 && <Notice c="warn">{plural(c.counts.pending, 'message is', 'messages are')} still being processed; a report generated now records them as pending.</Notice>}
            <button class="btn btn-primary" disabled={busy || formats.size === 0 || (scope === 'batch' && !batchId)} onClick={() => void generate()}>
              {busy ? 'Generating…' : 'Generate report'}
            </button>
            <div class="xs faint">
              Every report separates observed facts, engine inferences and external intelligence, lists limitations and records the engine version, configuration hash and intelligence snapshot behind each result. Generation is recorded in the audit log.
            </div>
          </div>
        </Panel>
      </div>
    </div>
  );
}
