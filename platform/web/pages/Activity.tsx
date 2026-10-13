// Case activity: who did what (audit trail) and what the pipeline did (processing events).
import { useApi } from '../lib/hooks';
import { setQuery, useRoute } from '../lib/router';
import { human, short } from '../lib/format';
import { useCase } from '../components/Shell';
import { Empty, ErrorBox, Loading, Panel, Tabs, Time } from '../components/ui';

interface ActivityData {
  audit: { type: 'audit'; seq: number; ts: number; user: string | null; action: string; target: string | null; details: unknown }[];
  processing: { type: 'processing'; ts: number; subjectType: string; subjectId: string; kind: string; detail: unknown }[];
}

export function ActivityPage() {
  const { c } = useCase();
  const { query } = useRoute();
  const tab = (query.get('tab') as 'audit' | 'processing' | null) ?? 'audit';
  const d = useApi<ActivityData>(`/api/cases/${c.id}/activity`, { limit: 500 }, { poll: 10_000 });
  return (
    <div class="page">
      <div class="page-head">
        <div>
          <div class="eyebrow">Accountability</div>
          <h1>Activity</h1>
        </div>
      </div>
      <Panel tight>
        <Tabs
          value={tab}
          onChange={(t) => setQuery({ tab: t === 'audit' ? null : t })}
          tabs={[
            { id: 'audit', label: 'Audit trail', count: d.data?.audit.length ?? null },
            { id: 'processing', label: 'Processing events', count: d.data?.processing.length ?? null },
          ]}
        />
        <ErrorBox error={d.error} retry={d.reload} />
        {!d.data ? (
          <Loading />
        ) : tab === 'audit' ? (
          d.data.audit.length === 0 ? (
            <Empty title="No audit entries" />
          ) : (
            <div class="table-wrap">
              <table class="t compact">
                <thead>
                  <tr>
                    <th style={{ width: '70px' }}>Seq</th>
                    <th style={{ width: '160px' }}>Time</th>
                    <th style={{ width: '120px' }}>User</th>
                    <th style={{ width: '200px' }}>Action</th>
                    <th>Details</th>
                  </tr>
                </thead>
                <tbody>
                  {d.data.audit.map((a) => (
                    <tr class="audit-row">
                      <td class="num mono">{a.seq}</td>
                      <td>
                        <Time ms={a.ts} />
                      </td>
                      <td>{a.user ?? 'system'}</td>
                      <td class="mono small">{a.action}</td>
                      <td class="wrap">
                        {a.target && <span class="mono xs">{short(a.target, 40)} </span>}
                        {a.details !== null && <div class="details break">{short(JSON.stringify(a.details), 400)}</div>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <div class="xs faint" style={{ padding: '8px 12px' }}>
                Entries are hash-chained and append-only (database triggers reject updates and deletes). An administrator can verify the whole chain under Administration.
              </div>
            </div>
          )
        ) : d.data.processing.length === 0 ? (
          <Empty title="No processing events" />
        ) : (
          <div class="table-wrap">
            <table class="t compact">
              <thead>
                <tr>
                  <th style={{ width: '160px' }}>Time</th>
                  <th style={{ width: '90px' }}>Subject</th>
                  <th style={{ width: '200px' }}>Event</th>
                  <th>Detail</th>
                </tr>
              </thead>
              <tbody>
                {d.data.processing.map((e) => (
                  <tr data-c={/fail|error/.test(e.kind) ? 'failed' : undefined}>
                    <td>
                      <Time ms={e.ts} />
                    </td>
                    <td class="small muted" title={e.subjectId}>
                      {e.subjectType}
                    </td>
                    <td>{human(e.kind)}</td>
                    <td class="wrap mono xs faint break">{e.detail !== null ? short(JSON.stringify(e.detail), 300) : ''}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
    </div>
  );
}
