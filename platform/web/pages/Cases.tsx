// Case list and case creation.
import { useState } from 'preact/hooks';
import { FolderPlus, Lock, Search, FolderOpen } from 'lucide-preact';
import { api } from '../lib/api';
import { useApi } from '../lib/hooks';
import { navigate } from '../lib/router';
import { session } from '../lib/session';
import { toastError, useStore } from '../lib/store';
import { fmtAgo, fmtBytes, fmtNum } from '../lib/format';
import type { CaseSummary } from '../lib/types';
import { Badge, Dialog, DistBar, Empty, ErrorBox, Field, Link, Loading, Notice } from '../components/ui';

export function CaseList() {
  const s = useStore(session);
  const cases = useApi<CaseSummary[]>('/api/cases', undefined, { poll: 15_000 });
  const [q, setQ] = useState('');
  const [status, setStatus] = useState<'open' | 'all' | 'closed' | 'archived'>('open');
  const [creating, setCreating] = useState(false);
  const list = (cases.data ?? []).filter((c) => (status === 'all' || c.status === status) && (!q || `${c.name} ${c.reference ?? ''} ${c.description ?? ''}`.toLowerCase().includes(q.toLowerCase())));
  return (
    <div class="page">
      <div class="page-head">
        <div>
          <div class="eyebrow">Investigations</div>
          <h1>Cases</h1>
        </div>
        <div class="actions">
          <div class="input-icon">
            <Search />
            <input class="input" placeholder="Filter cases" value={q} onInput={(e) => setQ((e.target as HTMLInputElement).value)} aria-label="Filter cases" />
          </div>
          <select class="select" value={status} onChange={(e) => setStatus((e.target as HTMLSelectElement).value as typeof status)} aria-label="Case status">
            <option value="open">Open</option>
            <option value="closed">Closed</option>
            <option value="archived">Archived</option>
            <option value="all">All statuses</option>
          </select>
          {s.user?.role !== 'viewer' && (
            <button class="btn btn-primary" onClick={() => setCreating(true)}>
              <FolderPlus /> New case
            </button>
          )}
        </div>
      </div>
      <ErrorBox error={cases.error} retry={cases.reload} />
      {!cases.data && !cases.error ? (
        <Loading />
      ) : list.length === 0 ? (
        <div class="panel">
          <Empty icon={<FolderOpen />} title={cases.data?.length ? 'No cases match' : 'No cases yet'}>
            {cases.data?.length ? 'Change the filter to see other cases.' : s.user?.role === 'viewer' ? 'A case lead must add you to a case.' : 'Create a case, then upload .eml, .emlx, .mbox or .msg evidence to it.'}
          </Empty>
        </div>
      ) : (
        <div class="case-grid">
          {list.map((c) => (
            <CaseCard c={c} />
          ))}
        </div>
      )}
      {creating && <NewCase onClose={() => setCreating(false)} />}
    </div>
  );
}

function CaseCard({ c }: { c: CaseSummary }) {
  const k = c.counts;
  return (
    <Link href={`/cases/${c.id}`} class="panel case-card">
      <div class="row" style={{ alignItems: 'flex-start' }}>
        <div class="grow">
          <div class="c-name trunc">{c.name}</div>
          <div class="c-meta">
            {c.reference && <span class="mono">{c.reference}</span>}
            <span>{c.myRole}</span>
            <span>updated {fmtAgo(c.updatedAt)}</span>
          </div>
        </div>
        <div class="row" style={{ gap: '4px' }}>
          {c.legalHold && (
            <Badge c="suspicious" title="Legal hold: the case cannot be deleted">
              <Lock /> Hold
            </Badge>
          )}
          <Badge c={c.status === 'open' ? 'ok' : undefined} outline={c.status !== 'open'}>
            {c.status}
          </Badge>
        </div>
      </div>
      <DistBar
        parts={[
          { c: 'malicious', n: k.malicious },
          { c: 'suspicious', n: k.suspicious },
          { c: 'inconclusive', n: k.inconclusive },
          { c: 'benign', n: k.benign },
          { c: 'failed', n: k.failed },
          { c: 'pending', n: k.pending },
        ]}
      />
      <div class="c-stats">
        <div class="c-stat">
          <div class="v">{fmtNum(k.messages)}</div>
          <div class="l">Messages</div>
        </div>
        <div class="c-stat">
          <div class="v" style={{ color: k.malicious ? 'var(--malicious)' : undefined }}>{fmtNum(k.malicious)}</div>
          <div class="l">Malicious</div>
        </div>
        <div class="c-stat">
          <div class="v" style={{ color: k.suspicious ? 'var(--suspicious)' : undefined }}>{fmtNum(k.suspicious)}</div>
          <div class="l">Suspicious</div>
        </div>
        <div class="c-stat">
          <div class="v">{fmtNum(k.threatClusters)}</div>
          <div class="l">Campaigns</div>
        </div>
      </div>
      <div class="small faint">
        {fmtNum(k.evidence)} evidence files · {fmtBytes(k.evidenceBytes)}
        {k.pending > 0 && <> · <span style={{ color: 'var(--pending)' }}>{fmtNum(k.pending)} processing</span></>}
      </div>
    </Link>
  );
}

function NewCase({ onClose }: { onClose: () => void }) {
  const s = useStore(session);
  const [f, setF] = useState({ name: '', reference: '', description: '', onlineLookups: false });
  const [busy, setBusy] = useState(false);
  const create = async (): Promise<void> => {
    setBusy(true);
    try {
      const c = await api.post<CaseSummary>('/api/cases', { name: f.name, reference: f.reference || null, description: f.description || null, onlineLookups: f.onlineLookups });
      onClose();
      navigate(`/cases/${c.id}/evidence`);
    } catch (e) {
      toastError(e);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Dialog
      title="New case"
      onClose={onClose}
      footer={
        <>
          <button class="btn" onClick={onClose}>
            Cancel
          </button>
          <button class="btn btn-primary" disabled={!f.name.trim() || busy} onClick={() => void create()}>
            Create case
          </button>
        </>
      }
    >
      <Field label="Name" id="cn">
        <input id="cn" class="input" value={f.name} maxLength={200} onInput={(e) => setF({ ...f, name: (e.target as HTMLInputElement).value })} />
      </Field>
      <Field label="Reference" id="cr" hint="Ticket or incident number (optional).">
        <input id="cr" class="input mono" value={f.reference} maxLength={100} onInput={(e) => setF({ ...f, reference: (e.target as HTMLInputElement).value })} />
      </Field>
      <Field label="Description" id="cd">
        <textarea id="cd" class="textarea" value={f.description} maxLength={4000} onInput={(e) => setF({ ...f, description: (e.target as HTMLTextAreaElement).value })} />
      </Field>
      {s.platform?.onlineLookupsAllowed ? (
        <label class="check">
          <input type="checkbox" checked={f.onlineLookups} onChange={(e) => setF({ ...f, onlineLookups: (e.target as HTMLInputElement).checked })} />
          <span>
            Allow online lookups <span class="faint small">(sends selected indicators to third-party services; off by default)</span>
          </span>
        </label>
      ) : (
        <Notice>Online lookups are disabled on this server. Indicators are matched only against locally synchronised feeds.</Notice>
      )}
    </Dialog>
  );
}
