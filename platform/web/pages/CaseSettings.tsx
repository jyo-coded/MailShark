// Case details, retention, online-lookup consent, membership and deletion.
import { useState } from 'preact/hooks';
import { Trash2, UserPlus } from 'lucide-preact';
import { api } from '../lib/api';
import { useApi } from '../lib/hooks';
import { navigate } from '../lib/router';
import { session } from '../lib/session';
import { toast, toastError, useStore } from '../lib/store';
import { fmtDate } from '../lib/format';
import type { CaseRole, Member } from '../lib/types';
import { useCase } from '../components/Shell';
import { Dialog, Field, Loading, Notice, Panel, Time } from '../components/ui';

export function CaseSettings() {
  const { c, reload } = useCase();
  const s = useStore(session);
  const lead = c.myRole === 'lead';
  const [f, setF] = useState({ name: c.name, reference: c.reference ?? '', description: c.description ?? '', retention: c.retentionUntil ? fmtDate(c.retentionUntil) : '' });
  const members = useApi<Member[]>(`/api/cases/${c.id}/members`);
  const users = useApi<{ id: string; username: string; displayName: string }[]>(lead ? '/api/users' : null);
  const [add, setAdd] = useState({ userId: '', role: 'investigator' as CaseRole });
  const [del, setDel] = useState(false);
  const [confirm, setConfirm] = useState('');
  const patch = async (body: Record<string, unknown>, msg = 'Case updated.'): Promise<void> => {
    try {
      await api.patch(`/api/cases/${c.id}`, body);
      toast(msg, 'success');
      reload();
    } catch (e) {
      toastError(e);
    }
  };
  const saveDetails = (): void => {
    const t = f.retention ? Date.parse(`${f.retention}T00:00:00Z`) : null;
    void patch({ name: f.name, reference: f.reference || null, description: f.description || null, retentionUntil: t !== null && Number.isFinite(t) ? t : null });
  };
  return (
    <div class="page">
      <div class="page-head">
        <div>
          <div class="eyebrow">Case</div>
          <h1>Case settings</h1>
        </div>
      </div>
      {!lead && <Notice>Only a case lead (or an administrator) can change these settings.</Notice>}
      <div class="grid grid-2" style={{ marginTop: 'var(--sp-3)' }}>
        <Panel title="Details">
          <div class="col" style={{ gap: 'var(--sp-3)' }}>
            <Field label="Name" id="n">
              <input id="n" class="input" disabled={!lead} value={f.name} onInput={(e) => setF({ ...f, name: (e.target as HTMLInputElement).value })} />
            </Field>
            <Field label="Reference" id="r">
              <input id="r" class="input mono" disabled={!lead} value={f.reference} onInput={(e) => setF({ ...f, reference: (e.target as HTMLInputElement).value })} />
            </Field>
            <Field label="Description" id="d">
              <textarea id="d" class="textarea" disabled={!lead} value={f.description} onInput={(e) => setF({ ...f, description: (e.target as HTMLTextAreaElement).value })} />
            </Field>
            <Field label="Retain until (UTC)" id="ret" hint="After this date the case is listed as overdue for deletion under Administration. Deletion is never automatic.">
              <input id="ret" type="date" class="input" disabled={!lead} value={f.retention} onInput={(e) => setF({ ...f, retention: (e.target as HTMLInputElement).value })} />
            </Field>
            {lead && (
              <div>
                <button class="btn btn-primary" onClick={saveDetails}>
                  Save details
                </button>
              </div>
            )}
          </div>
        </Panel>
        <div class="col" style={{ gap: 'var(--sp-3)' }}>
          <Panel title="Status and safeguards">
            <div class="col" style={{ gap: 'var(--sp-3)' }}>
              <Field label="Status" id="st" hint="Closed and archived cases are read-only for new evidence.">
                <select id="st" class="select" disabled={!lead} value={c.status} onChange={(e) => void patch({ status: (e.target as HTMLSelectElement).value })}>
                  <option value="open">Open</option>
                  <option value="closed">Closed</option>
                  <option value="archived">Archived</option>
                </select>
              </Field>
              <label class="check">
                <input type="checkbox" disabled={!lead} checked={c.legalHold} onChange={(e) => void patch({ legalHold: (e.target as HTMLInputElement).checked })} />
                Legal hold <span class="faint small">(blocks deletion of the case and its evidence)</span>
              </label>
              <label class="check">
                <input type="checkbox" disabled={!lead || !s.platform?.onlineLookupsAllowed} checked={c.onlineLookups} onChange={(e) => void patch({ onlineLookups: (e.target as HTMLInputElement).checked })} />
                Allow online lookups
              </label>
              <div class="xs faint" style={{ marginTop: '-6px' }}>
                When on, investigators may send individual indicators of this case to third-party services (e.g. VirusTotal, OTX), and DKIM public keys are fetched over DNS during analysis. Off by default; bulk feeds are always matched locally without disclosure.
                {!s.platform?.onlineLookupsAllowed && ' Disabled server-wide (MAILSHARK_ALLOW_ONLINE_LOOKUPS=false).'}
              </div>
            </div>
          </Panel>
          <Panel title="Members" tight>
            {!members.data ? (
              <Loading />
            ) : (
              <table class="t compact">
                <tbody>
                  {members.data.map((m) => (
                    <tr>
                      <td>
                        {m.display_name} <span class="mono xs faint">{m.username}</span>
                      </td>
                      <td style={{ width: '130px' }}>
                        {lead ? (
                          <select
                            class="select"
                            value={m.role}
                            onChange={(e) =>
                              void api
                                .post(`/api/cases/${c.id}/members`, { userId: m.user_id, role: (e.target as HTMLSelectElement).value })
                                .then(members.reload)
                                .catch(toastError)
                            }
                          >
                            <option value="lead">Lead</option>
                            <option value="investigator">Investigator</option>
                            <option value="viewer">Viewer</option>
                          </select>
                        ) : (
                          m.role
                        )}
                      </td>
                      <td style={{ width: '150px' }} class="small muted">
                        added <Time ms={m.added_at} seconds={false} />
                      </td>
                      <td style={{ width: '40px' }}>
                        {lead && (
                          <button class="btn btn-ghost btn-sm btn-icon" aria-label={`Remove ${m.username}`} onClick={() => void api.del(`/api/cases/${c.id}/members/${m.user_id}`).then(members.reload).catch(toastError)}>
                            <Trash2 />
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
            {lead && users.data && (
              <div class="toolbar" style={{ borderTop: '1px solid var(--line)', borderBottom: 0 }}>
                <select class="select grow" value={add.userId} onChange={(e) => setAdd({ ...add, userId: (e.target as HTMLSelectElement).value })} aria-label="User to add">
                  <option value="">Add a user…</option>
                  {users.data
                    .filter((u) => !members.data?.some((m) => m.user_id === u.id))
                    .map((u) => (
                      <option value={u.id}>
                        {u.displayName} ({u.username})
                      </option>
                    ))}
                </select>
                <select class="select" value={add.role} onChange={(e) => setAdd({ ...add, role: (e.target as HTMLSelectElement).value as CaseRole })} aria-label="Role">
                  <option value="investigator">Investigator</option>
                  <option value="viewer">Viewer</option>
                  <option value="lead">Lead</option>
                </select>
                <button
                  class="btn"
                  disabled={!add.userId}
                  onClick={() =>
                    void api
                      .post(`/api/cases/${c.id}/members`, add)
                      .then(() => {
                        setAdd({ userId: '', role: 'investigator' });
                        members.reload();
                      })
                      .catch(toastError)
                  }
                >
                  <UserPlus /> Add
                </button>
              </div>
            )}
          </Panel>
          {lead && (
            <Panel title="Delete case">
              <div class="col">
                <span class="small muted">Deletes the case, its analyses, reports and any stored evidence no other case references. The deletion (with the evidence hashes) stays in the audit log.</span>
                <div>
                  <button class="btn btn-danger" disabled={c.legalHold} onClick={() => setDel(true)} title={c.legalHold ? 'Lift the legal hold first' : undefined}>
                    <Trash2 /> Delete case…
                  </button>
                </div>
              </div>
            </Panel>
          )}
        </div>
      </div>
      {del && (
        <Dialog
          title="Delete case permanently"
          onClose={() => setDel(false)}
          footer={
            <>
              <button class="btn" onClick={() => setDel(false)}>
                Cancel
              </button>
              <button
                class="btn btn-danger"
                disabled={confirm !== c.name}
                onClick={() =>
                  void api
                    .del(`/api/cases/${c.id}`, { confirm })
                    .then(() => {
                      toast('Case deleted.', 'success');
                      navigate('/');
                    })
                    .catch(toastError)
                }
              >
                Delete permanently
              </button>
            </>
          }
        >
          <Notice c="danger">This cannot be undone. Make sure the evidence originals are preserved elsewhere if they are still needed.</Notice>
          <Field label={`Type the case name (${c.name}) to confirm`} id="cf">
            <input id="cf" class="input" value={confirm} onInput={(e) => setConfirm((e.target as HTMLInputElement).value)} />
          </Field>
        </Dialog>
      )}
    </div>
  );
}
