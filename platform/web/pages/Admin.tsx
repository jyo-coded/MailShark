// Administration: users, the platform audit log (with chain verification) and system state.
import { useState } from 'preact/hooks';
import { ShieldCheck, UserPlus } from 'lucide-preact';
import { api } from '../lib/api';
import { useApi } from '../lib/hooks';
import { setQuery, useRoute } from '../lib/router';
import { session } from '../lib/session';
import { toast, toastError, useStore } from '../lib/store';
import { fmtBytes, fmtDate, short } from '../lib/format';
import type { AuditEntry, Role, User } from '../lib/types';
import { Badge, Dialog, Empty, ErrorBox, Field, KV, Link, Loading, Mono, Notice, Panel, Tabs, Time } from '../components/ui';

function Users() {
  const me = useStore(session).user;
  const users = useApi<User[]>('/api/users');
  const [creating, setCreating] = useState(false);
  const [reset, setReset] = useState<User | null>(null);
  const [f, setF] = useState({ username: '', displayName: '', password: '', role: 'investigator' as Role });
  const [pw, setPw] = useState('');
  const update = (id: string, body: Record<string, unknown>): void =>
    void api
      .patch(`/api/users/${id}`, body)
      .then(users.reload)
      .catch(toastError);
  return (
    <>
      <div class="toolbar">
        <span class="small muted grow">Platform roles: administrators manage users and sources and can access every case; investigators create cases; viewers only read cases they are added to.</span>
        <button class="btn btn-primary btn-sm" onClick={() => setCreating(true)}>
          <UserPlus /> New user
        </button>
      </div>
      <ErrorBox error={users.error} retry={users.reload} />
      {!users.data ? (
        <Loading />
      ) : (
        <table class="t">
          <thead>
            <tr>
              <th>User</th>
              <th style={{ width: '150px' }}>Role</th>
              <th style={{ width: '170px' }}>Last sign-in</th>
              <th style={{ width: '120px' }}>Created</th>
              <th style={{ width: '220px' }} />
            </tr>
          </thead>
          <tbody>
            {users.data.map((u) => (
              <tr data-c={u.disabled ? 'failed' : undefined}>
                <td>
                  {u.displayName} <span class="mono xs faint">{u.username}</span> {u.disabled && <Badge c="failed">disabled</Badge>}
                </td>
                <td>
                  <select class="select" value={u.role} disabled={u.id === me?.id} onChange={(e) => update(u.id, { role: (e.target as HTMLSelectElement).value })}>
                    <option value="admin">Administrator</option>
                    <option value="investigator">Investigator</option>
                    <option value="viewer">Viewer</option>
                  </select>
                </td>
                <td>
                  <Time ms={u.lastLoginAt} />
                </td>
                <td class="mono small">{fmtDate(u.createdAt)}</td>
                <td>
                  <div class="row">
                    <button class="btn btn-sm" onClick={() => setReset(u)}>
                      Reset password
                    </button>
                    {u.id !== me?.id && (
                      <button class="btn btn-sm" onClick={() => update(u.id, { disabled: !u.disabled })}>
                        {u.disabled ? 'Enable' : 'Disable'}
                      </button>
                    )}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {creating && (
        <Dialog
          title="New user"
          onClose={() => setCreating(false)}
          footer={
            <>
              <button class="btn" onClick={() => setCreating(false)}>
                Cancel
              </button>
              <button
                class="btn btn-primary"
                disabled={!f.username || f.password.length < 12}
                onClick={() =>
                  void api
                    .post('/api/users', f)
                    .then(() => {
                      setCreating(false);
                      setF({ username: '', displayName: '', password: '', role: 'investigator' });
                      users.reload();
                      toast('User created. Share the initial password through a separate channel.', 'success');
                    })
                    .catch(toastError)
                }
              >
                Create
              </button>
            </>
          }
        >
          <Field label="Username" id="nu">
            <input id="nu" class="input" autocomplete="off" value={f.username} onInput={(e) => setF({ ...f, username: (e.target as HTMLInputElement).value })} />
          </Field>
          <Field label="Display name" id="nd">
            <input id="nd" class="input" value={f.displayName} onInput={(e) => setF({ ...f, displayName: (e.target as HTMLInputElement).value })} />
          </Field>
          <Field label="Initial password" id="np" hint="At least 12 characters.">
            <input id="np" class="input" type="password" autocomplete="new-password" value={f.password} onInput={(e) => setF({ ...f, password: (e.target as HTMLInputElement).value })} />
          </Field>
          <Field label="Role" id="nr">
            <select id="nr" class="select" value={f.role} onChange={(e) => setF({ ...f, role: (e.target as HTMLSelectElement).value as Role })}>
              <option value="investigator">Investigator</option>
              <option value="viewer">Viewer</option>
              <option value="admin">Administrator</option>
            </select>
          </Field>
        </Dialog>
      )}
      {reset && (
        <Dialog
          title={`Reset password: ${reset.username}`}
          onClose={() => setReset(null)}
          footer={
            <>
              <button class="btn" onClick={() => setReset(null)}>
                Cancel
              </button>
              <button
                class="btn btn-primary"
                disabled={pw.length < 12}
                onClick={() =>
                  void api
                    .post(`/api/users/${reset.id}/password`, { password: pw })
                    .then(() => {
                      setReset(null);
                      setPw('');
                      toast('Password reset. Existing sessions of the user were signed out.', 'success');
                    })
                    .catch(toastError)
                }
              >
                Reset
              </button>
            </>
          }
        >
          <Field label="New password" id="rp" hint="At least 12 characters.">
            <input id="rp" class="input" type="password" autocomplete="new-password" value={pw} onInput={(e) => setPw((e.target as HTMLInputElement).value)} />
          </Field>
        </Dialog>
      )}
    </>
  );
}

function AuditLog() {
  const log = useApi<AuditEntry[]>('/api/admin/audit', { limit: 500 });
  const [v, setV] = useState<{ ok: boolean; entries: number; brokenAt: number | null; head: string } | null>(null);
  return (
    <>
      <div class="toolbar">
        <span class="small muted grow">Append-only, hash-chained log of authentication, case, evidence, intelligence and report actions.</span>
        <button class="btn btn-sm" onClick={() => void api.get<typeof v>('/api/admin/audit/verify').then(setV).catch(toastError)}>
          <ShieldCheck /> Verify chain
        </button>
      </div>
      {v && (
        <div style={{ padding: '12px' }}>
          <Notice c={v.ok ? 'info' : 'danger'}>
            {v.ok ? (
              <>
                Chain intact: {v.entries.toLocaleString()} entries verified, head <span class="mono">{short(v.head, 20)}</span>. This detects modification of stored entries; it cannot detect an attacker who rewrites the whole database and chain, so export the head hash periodically to an independent system.
              </>
            ) : (
              <>Chain broken at entry {v.brokenAt}: the audit log was modified outside the application.</>
            )}
          </Notice>
        </div>
      )}
      <ErrorBox error={log.error} retry={log.reload} />
      {!log.data ? (
        <Loading />
      ) : log.data.length === 0 ? (
        <Empty title="Empty log" />
      ) : (
        <div class="table-wrap" style={{ maxHeight: '70vh' }}>
          <table class="t compact">
            <thead>
              <tr>
                <th style={{ width: '70px' }}>Seq</th>
                <th style={{ width: '160px' }}>Time</th>
                <th style={{ width: '120px' }}>User</th>
                <th style={{ width: '200px' }}>Action</th>
                <th style={{ width: '120px' }}>Case</th>
                <th>Details</th>
                <th style={{ width: '110px' }}>IP</th>
              </tr>
            </thead>
            <tbody>
              {log.data.map((a) => (
                <tr data-c={/fail|integrity/.test(a.action) ? 'suspicious' : undefined}>
                  <td class="num mono">{a.seq}</td>
                  <td>
                    <Time ms={a.ts} />
                  </td>
                  <td>{a.username ?? 'system'}</td>
                  <td class="mono small">{a.action}</td>
                  <td class="small">{a.case_id ? <Link href={`/cases/${a.case_id}/activity`}>{short(a.case_id, 13)}</Link> : '—'}</td>
                  <td class="wrap mono xs faint break">
                    {a.target ? `${short(a.target, 30)} ` : ''}
                    {a.details ? short(a.details, 300) : ''}
                  </td>
                  <td class="mono xs">{a.ip ?? ''}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
}

interface SystemInfo {
  workers: { size: number; busy: number; queued: number };
  queue: { queued: number; running: number; failed24h: number };
  retentionOverdue: { id: string; name: string; retentionUntil: number; legalHold: number }[];
  failedJobs: { id: number; kind: string; caseId: string | null; ref: string; attempts: number; lastError: string | null; updatedAt: number }[];
  dataDir: string;
  limits: { filesPerBatch: number; fileBytes: number; batchBytes: number; messagesPerContainer: number; rawViewBytes: number };
  thresholds: { caution: number; danger: number; coverageFloor: number };
}

function System() {
  const d = useApi<SystemInfo>('/api/admin/system', undefined, { poll: 10_000 });
  if (d.error) return <ErrorBox error={d.error} retry={d.reload} />;
  if (!d.data) return <Loading />;
  const x = d.data;
  return (
    <div class="grid grid-2" style={{ padding: '16px' }}>
      <Panel title="Processing">
        <KV
          rows={[
            ['Workers', `${x.workers.busy} busy of ${x.workers.size} · ${x.workers.queued} tasks waiting`],
            ['Job queue', `${x.queue.queued} queued · ${x.queue.running} running · ${x.queue.failed24h} failed in 24 h`],
            ['Data directory', <span class="mono break">{x.dataDir}</span>],
          ]}
        />
      </Panel>
      <Panel title="Limits and thresholds">
        <KV
          rows={[
            ['Batch', `${x.limits.filesPerBatch} files · ${fmtBytes(x.limits.batchBytes)}`],
            ['File', fmtBytes(x.limits.fileBytes)],
            ['Messages per container', x.limits.messagesPerContainer.toLocaleString()],
            ['Classification', `suspicious ≥ ${x.thresholds.caution} · malicious ≥ ${x.thresholds.danger} · coverage floor ${x.thresholds.coverageFloor}`],
          ]}
        />
      </Panel>
      <Panel title="Retention overdue" tight>
        {x.retentionOverdue.length === 0 ? (
          <Empty title="Nothing overdue" />
        ) : (
          <table class="t compact">
            <tbody>
              {x.retentionOverdue.map((c) => (
                <tr>
                  <td>
                    <Link href={`/cases/${c.id}/settings`}>{c.name}</Link>
                  </td>
                  <td class="mono small">{fmtDate(c.retentionUntil)}</td>
                  <td>{c.legalHold ? <Badge c="suspicious">legal hold</Badge> : null}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Panel>
      <Panel title="Failed jobs" tight>
        {x.failedJobs.length === 0 ? (
          <Empty title="No failed jobs" />
        ) : (
          <table class="t compact">
            <tbody>
              {x.failedJobs.map((j) => (
                <tr>
                  <td style={{ width: '80px' }}>{j.kind}</td>
                  <td class="wrap small">{j.lastError}</td>
                  <td style={{ width: '50px' }} class="num">
                    {j.attempts}×
                  </td>
                  <td style={{ width: '150px' }}>
                    <Time ms={j.updatedAt} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Panel>
    </div>
  );
}

export function Admin() {
  const { query } = useRoute();
  const tab = (query.get('tab') as 'users' | 'audit' | 'system' | null) ?? 'users';
  return (
    <div class="page">
      <div class="page-head">
        <div>
          <div class="eyebrow">Platform</div>
          <h1>Administration</h1>
        </div>
      </div>
      <Panel tight>
        <Tabs
          value={tab}
          onChange={(t) => setQuery({ tab: t === 'users' ? null : t })}
          tabs={[
            { id: 'users', label: 'Users' },
            { id: 'audit', label: 'Audit log' },
            { id: 'system', label: 'System' },
          ]}
        />
        {tab === 'users' ? <Users /> : tab === 'audit' ? <AuditLog /> : <System />}
      </Panel>
    </div>
  );
}
