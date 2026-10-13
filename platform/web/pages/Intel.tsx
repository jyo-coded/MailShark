// Intelligence sources: what each provides, its terms and access, and its real current state.
// A source that is not configured or has never synchronised is shown as such, never as connected.
import type { ComponentChildren } from 'preact';
import { useState } from 'preact/hooks';
import { RefreshCw } from 'lucide-preact';
import { api } from '../lib/api';
import { useApi } from '../lib/hooks';
import { session } from '../lib/session';
import { toast, toastError, useStore } from '../lib/store';
import { fmtBytes, fmtNum, human } from '../lib/format';
import type { SourceInfo } from '../lib/types';
import { Badge, Drawer, ErrorBox, KV, Loading, Mono, Notice, Panel, Time } from '../components/ui';

interface SyncRow {
  started_at: number;
  finished_at: number | null;
  status: string;
  records: number | null;
  events: number | null;
  bytes: number | null;
  snapshot_sha256: string | null;
  error: string | null;
}

const KIND_LABEL: Record<string, string> = { feed: 'Bulk feed (matched locally)', enrichment: 'Enrichment data', lookup: 'Per-indicator lookup (online)' };
const ACCESS_LABEL: Record<string, string> = { public: 'Public download', 'free-key': 'Free API key required', 'key-optional': 'Works without key; key raises limits', 'self-hosted': 'Your own instance' };
const ATTR_LABEL: Record<string, string> = { 'campaign-events': 'Names events / campaigns', 'malware-family': 'Names malware families', 'indicator-only': 'Indicators only (no attribution)', enrichment: 'Context, not a verdict' };

function SourceDrawer({ s, onClose }: { s: SourceInfo; onClose: () => void }) {
  const h = useApi<SyncRow[]>(s.kind === 'lookup' ? null : `/api/intel/sources/${s.id}/history`);
  return (
    <Drawer title={s.name} sub={s.provider} onClose={onClose}>
      <KV
        rows={[
          ['Type', KIND_LABEL[s.kind] ?? s.kind],
          ['Provides', s.provides],
          ['Attribution quality', ATTR_LABEL[s.attribution] ?? s.attribution],
          ['Access', ACCESS_LABEL[s.access] ?? s.access],
          ['Licence / terms', s.license],
          ['Homepage', <span class="mono small break">{s.homepage}</span>],
          ['Refresh interval', s.kind === 'lookup' ? 'on demand' : `${s.intervalHours} h`],
          ['State', <Badge c={s.freshness}>{human(s.freshness)}</Badge>],
          ...(s.missing.length ? ([['Configuration', `Set ${s.missing.join(', ')} in the server environment and restart.`]] as [string, string][]) : []),
          ['Records', `${fmtNum(s.recordCount)} indicators${s.eventCount ? ` · ${fmtNum(s.eventCount)} events` : ''}`],
          ['Last success', <Time ms={s.lastSuccess} />],
          ['Next due', <Time ms={s.nextDue} />],
          ['Snapshot SHA-256', <Mono value={s.snapshotSha256} />],
          ...(s.lastError ? ([['Last error', <span style={{ color: 'var(--failed)' }}>{s.lastError}</span>]] as [string, ComponentChildren][]) : []),
        ]}
      />
      {s.kind !== 'lookup' && (
        <div>
          <div class="section-title">Synchronisation history</div>
          {!h.data ? (
            <Loading />
          ) : h.data.length === 0 ? (
            <span class="small faint">Never attempted.</span>
          ) : (
            <table class="t compact">
              <thead>
                <tr>
                  <th style={{ width: '160px' }}>Started</th>
                  <th style={{ width: '90px' }}>Status</th>
                  <th class="num">Records</th>
                  <th class="num">Bytes</th>
                  <th>Error</th>
                </tr>
              </thead>
              <tbody>
                {h.data.map((r) => (
                  <tr data-c={r.status === 'error' ? 'failed' : undefined}>
                    <td>
                      <Time ms={r.started_at} />
                    </td>
                    <td>{r.status}</td>
                    <td class="num">{fmtNum(r.records)}</td>
                    <td class="num">{fmtBytes(r.bytes)}</td>
                    <td class="wrap small">{r.error ?? ''}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}
    </Drawer>
  );
}

export function IntelSources() {
  const s = useStore(session);
  const admin = s.user?.role === 'admin';
  const d = useApi<{ sources: SourceInfo[]; snapshot: string; autoSync: boolean; onlineLookupsAllowed: boolean }>('/api/intel/sources', undefined, { poll: 10_000 });
  const [open, setOpen] = useState<string | null>(null);
  const sync = async (id: string): Promise<void> => {
    try {
      await api.post(`/api/intel/sources/${id}/sync`);
      toast('Synchronisation queued.', 'success');
      setTimeout(d.reload, 1000);
    } catch (e) {
      toastError(e);
    }
  };
  const toggle = async (id: string, enabled: boolean): Promise<void> => {
    try {
      await api.patch(`/api/intel/sources/${id}`, { enabled });
      d.reload();
    } catch (e) {
      toastError(e);
    }
  };
  const groups: { kind: SourceInfo['kind']; title: string; note: string }[] = [
    { kind: 'feed', title: 'Bulk feeds', note: 'Downloaded on a schedule and matched locally. Case data never leaves the server.' },
    { kind: 'enrichment', title: 'Enrichment', note: 'Context used to discount common infrastructure (popularity ranks, network owners). Never a verdict by itself.' },
    { kind: 'lookup', title: 'Online lookups', note: 'Query one indicator at a time. Used only when a case explicitly allows online lookups, and audit-logged.' },
  ];
  const selected = d.data?.sources.find((x) => x.id === open) ?? null;
  return (
    <div class="page">
      <div class="page-head">
        <div>
          <div class="eyebrow">Platform</div>
          <h1>Intelligence sources</h1>
        </div>
        {d.data && (
          <div class="actions small muted">
            Current snapshot <Mono value={d.data.snapshot} max={16} /> · scheduled sync {d.data.autoSync ? 'on' : 'off (MAILSHARK_INTEL_AUTOSYNC=false)'}
          </div>
        )}
      </div>
      <ErrorBox error={d.error} retry={d.reload} />
      {!d.data ? (
        <Loading />
      ) : (
        <div class="col" style={{ gap: 'var(--sp-3)' }}>
          <Notice>
            Each analysis records the intelligence snapshot it was matched against, so a result can be reproduced or explained later. A listing in a feed is external information about an indicator, not proof about a specific message; popular domains and shared platforms are kept as context only.
          </Notice>
          {groups.map((g) => {
            const rows = d.data!.sources.filter((x) => x.kind === g.kind);
            if (!rows.length) return null;
            return (
              <Panel title={g.title} actions={<span class="small muted">{g.note}</span>} tight>
                <div class="table-wrap">
                  <table class="t">
                    <thead>
                      <tr>
                        <th>Source</th>
                        <th style={{ width: '120px' }}>State</th>
                        <th class="num" style={{ width: '110px' }}>
                          Records
                        </th>
                        <th style={{ width: '160px' }}>Last success</th>
                        <th style={{ width: '22%' }}>Access · attribution</th>
                        {admin && <th style={{ width: '150px' }} />}
                      </tr>
                    </thead>
                    <tbody>
                      {rows.map((x) => (
                        <tr class="clickable" data-c={x.freshness === 'unavailable' ? 'failed' : undefined} onClick={() => setOpen(x.id)}>
                          <td class="wrap">
                            <div class="src-name">{x.name}</div>
                            <div class="src-sub">{x.provides}</div>
                          </td>
                          <td title={x.lastError ?? undefined}>
                            <Badge c={x.freshness}>{human(x.freshness)}</Badge>
                            {x.missing.length > 0 && <div class="xs faint mono">{x.missing.join(', ')}</div>}
                          </td>
                          <td class="num">
                            {x.kind === 'lookup' ? '—' : fmtNum(x.recordCount)}
                            {x.eventCount > 0 && <div class="xs faint">{fmtNum(x.eventCount)} events</div>}
                          </td>
                          <td>
                            <Time ms={x.lastSuccess} />
                          </td>
                          <td class="wrap small muted">
                            {ACCESS_LABEL[x.access] ?? x.access}
                            <div class="xs faint">{ATTR_LABEL[x.attribution] ?? x.attribution}</div>
                          </td>
                          {admin && (
                            <td onClick={(e) => e.stopPropagation()}>
                              <div class="row" style={{ gap: '6px' }}>
                                {x.kind !== 'lookup' && (
                                  <button class="btn btn-sm" disabled={!x.enabled || x.missing.length > 0 || x.freshness === 'syncing'} onClick={() => void sync(x.id)} title="Synchronise now">
                                    <RefreshCw /> Sync
                                  </button>
                                )}
                                <label class="check small" title="Enable or disable this source">
                                  <input type="checkbox" checked={x.enabled} onChange={(e) => void toggle(x.id, (e.target as HTMLInputElement).checked)} /> on
                                </label>
                              </div>
                            </td>
                          )}
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </Panel>
            );
          })}
        </div>
      )}
      {selected && <SourceDrawer s={selected} onClose={() => setOpen(null)} />}
    </div>
  );
}
