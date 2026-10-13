// Campaign intelligence: local clusters (formed only from evidence in this case) and associations with
// externally reported campaigns/events (reported vs possible), kept strictly apart.
import { useState } from 'preact/hooks';
import { Boxes, FileText, Inbox, Radar, Waypoints } from 'lucide-preact';
import { api } from '../lib/api';
import { useApi } from '../lib/hooks';
import { href, navigate, setQuery, useRoute } from '../lib/router';
import { toast, toastError } from '../lib/store';
import { fmtDate, human, pct, plural, short } from '../lib/format';
import type { ClusterDetail, ClusterRow, ExternalAssociation } from '../lib/types';
import { useCase } from '../components/Shell';
import { Badge, ClassBadge, Drawer, Empty, ErrorBox, KV, Link, Loading, Notice, SafeRef, Tabs, Time } from '../components/ui';

const VERDICT_C: Record<string, string> = { threat: 'malicious', mixed: 'suspicious', bulk: 'benign' };

function ClusterDrawer({ id, onClose }: { id: string; onClose: () => void }) {
  const { c } = useCase();
  const d = useApi<ClusterDetail>(`/api/cases/${c.id}/clusters/${id}`, undefined, { keep: false });
  const x = d.data;
  const report = async (): Promise<void> => {
    if (!x) return;
    try {
      const r = await api.post<{ id: string }>(`/api/cases/${c.id}/reports`, { format: 'json', scope: 'messages', messageIds: x.messages.map((m) => m.id) });
      toast('Report generated for the cluster members.', 'success');
      navigate(href(`/cases/${c.id}/reports`, { r: r.id }));
    } catch (e) {
      toastError(e);
    }
  };
  return (
    <Drawer
      title={x?.label ?? 'Cluster'}
      sub={x ? `${plural(x.size, 'message')} · ${x.confidence} confidence · ${x.verdict}` : undefined}
      onClose={onClose}
      actions={
        x && (
          <>
            <Link class="btn btn-sm" href={href(`/cases/${c.id}/messages`, { cluster: x.id })}>
              <Inbox /> Messages
            </Link>
            <Link class="btn btn-sm" href={href(`/cases/${c.id}/graph`, { cluster: x.id })}>
              <Waypoints /> Graph
            </Link>
            <button class="btn btn-sm" onClick={() => void report()}>
              <FileText /> Report
            </button>
          </>
        )
      }
    >
      <ErrorBox error={d.error} retry={d.reload} />
      {!x ? (
        <Loading />
      ) : (
        <>
          <Notice>
            A local cluster is an inference: these messages share specific artifacts and/or are highly similar. It does not by itself attribute them to an actor or to an externally reported campaign.
          </Notice>
          <KV
            rows={[
              ['Verdict', <Badge c={VERDICT_C[x.verdict]}>{x.verdict}</Badge>],
              ['Confidence', `${x.confidence} · cohesion ${pct(x.cohesion)} · density ${pct(x.density)} · ${x.exactEdges} exact relationships`],
              ['Active', `${fmtDate(x.firstSeen)} → ${fmtDate(x.lastSeen)}`],
              ['Senders', x.profile.senders.slice(0, 8).join(', ') || '—'],
              ['Link domains', x.profile.domains.slice(0, 8).join(', ') || '—'],
              ['Method', x.method],
            ]}
          />
          <div>
            <div class="section-title">What stays the same (invariants)</div>
            <div class="row wrap" style={{ gap: '4px' }}>
              {x.profile.invariants.length === 0 ? (
                <span class="small faint">none</span>
              ) : (
                x.profile.invariants.map((i) => (
                  <span class="inv-chip" title={`${i.values.join(', ')} · on ${pct(i.coverage)} of members`}>
                    {i.label}: {short(i.values[0] ?? '', 40)}
                  </span>
                ))
              )}
            </div>
            <div class="section-title" style={{ marginTop: '10px' }}>
              What the sender rotates
            </div>
            <div class="row wrap" style={{ gap: '4px' }}>
              {x.profile.rotated.length === 0 ? (
                <span class="small faint">none</span>
              ) : (
                x.profile.rotated.map((i) => (
                  <span class="inv-chip" data-k="rotated" title={i.values.join(', ')}>
                    {i.label} ({i.values.length} values)
                  </span>
                ))
              )}
            </div>
          </div>
          <div>
            <div class="section-title">Shared indicators</div>
            <table class="t compact">
              <tbody>
                {x.sharedIndicators.map((s) => (
                  <tr>
                    <td style={{ width: '30%' }} class="small">
                      {s.family}
                    </td>
                    <td class="mono" title={s.value}>
                      {s.value}
                    </td>
                    <td class="num" style={{ width: '80px' }} title={s.discounts.length ? `discounted: ${s.discounts.join(', ')}` : undefined}>
                      {s.strength.toFixed(2)}
                    </td>
                    <td class="num" style={{ width: '50px' }}>
                      {s.messages}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {Array.isArray(x.external) && x.external.length > 0 && (
            <div>
              <div class="section-title">External records overlapping this cluster</div>
              {x.external.map((e) => (
                <div class="small">
                  <Badge c="intel">{e.source}</Badge> {e.name} · <span class="assess" data-a={e.assessment}>{human(e.assessment)}</span> ({e.confidence})
                </div>
              ))}
            </div>
          )}
          <div>
            <div class="section-title">Members ({x.messages.length})</div>
            <table class="t compact">
              <thead>
                <tr>
                  <th style={{ width: '110px' }}>Class</th>
                  <th>Subject</th>
                  <th style={{ width: '150px' }}>Sent</th>
                  <th class="num" style={{ width: '80px' }}>
                    Membership
                  </th>
                </tr>
              </thead>
              <tbody>
                {x.messages.map((m) => (
                  <tr class="clickable" data-c={m.class ?? undefined} onClick={() => navigate(href(`/cases/${c.id}/messages`, { cluster: x.id, m: m.id }))}>
                    <td>
                      <ClassBadge c={m.class} />
                    </td>
                    <td title={m.from ?? ''}>{m.subject || '(no subject)'}</td>
                    <td>
                      <Time ms={m.sentAt} />
                    </td>
                    <td class="num">{m.membership.toFixed(2)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div>
            <div class="section-title">Relationships ({x.relationships.length})</div>
            <table class="t compact">
              <tbody>
                {x.relationships.slice(0, 200).map((r) => {
                  const a = x.messages.find((m) => m.id === r.a);
                  const b = x.messages.find((m) => m.id === r.b);
                  return (
                    <tr>
                      <td style={{ width: '80px' }}>
                        <Badge c={r.tier === 'exact' ? 'malicious' : 'suspicious'}>{r.tier}</Badge>
                      </td>
                      <td class="wrap small">
                        {short(a?.subject ?? r.a, 40)} ↔ {short(b?.subject ?? r.b, 40)}
                        <div class="xs faint">{r.evidence.hardLink ?? r.evidence.shared.slice(0, 3).map((s) => `${s.family}: ${short(s.value, 30)}`).join(' · ')}</div>
                      </td>
                      <td class="num" style={{ width: '60px' }}>
                        {r.score.toFixed(2)}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
            {x.relationships.length > 200 && <div class="xs faint">Showing the 200 strongest of {x.relationships.length} relationships.</div>}
          </div>
        </>
      )}
    </Drawer>
  );
}

export function Campaigns() {
  const { c } = useCase();
  const { query } = useRoute();
  const tab = (query.get('tab') as 'local' | 'external' | null) ?? 'local';
  const selected = query.get('c');
  const clusters = useApi<ClusterRow[]>(`/api/cases/${c.id}/clusters`);
  const external = useApi<ExternalAssociation[]>(`/api/cases/${c.id}/external-campaigns`);
  const [hideBulk, setHideBulk] = useState(false);
  const rows = (clusters.data ?? []).filter((x) => !hideBulk || x.verdict !== 'bulk');
  return (
    <div class="page">
      <div class="page-head">
        <div>
          <div class="eyebrow">Campaign intelligence</div>
          <h1>Campaigns</h1>
        </div>
        <div class="actions small muted">{c.correlatedAt ? <>Correlated <Time ms={c.correlatedAt} ago /></> : 'Correlation has not run yet'}</div>
      </div>
      <div class="panel">
        <Tabs
          value={tab}
          onChange={(t) => setQuery({ tab: t === 'local' ? null : t })}
          tabs={[
            { id: 'local', label: <><Boxes size={14} /> Local clusters</>, count: clusters.data?.length ?? null },
            { id: 'external', label: <><Radar size={14} /> External associations</>, count: external.data?.length ?? null },
          ]}
        />
        {tab === 'local' ? (
          <>
            <div class="toolbar">
              <span class="small muted grow">Groups of messages in this case linked by shared, specific evidence (exact) or by combined weaker evidence and similarity (probable). Clusters never span cases.</span>
              <label class="check small">
                <input type="checkbox" checked={hideBulk} onChange={(e) => setHideBulk((e.target as HTMLInputElement).checked)} /> Hide bulk / newsletter clusters
              </label>
            </div>
            <ErrorBox error={clusters.error} retry={clusters.reload} />
            {!clusters.data ? (
              <Loading />
            ) : rows.length === 0 ? (
              <Empty icon={<Boxes />} title="No clusters">
                {c.correlatedAt ? 'No two messages share enough evidence to be related.' : 'Correlation runs automatically after the analyses of a batch have finished.'}
              </Empty>
            ) : (
              <div class="table-wrap">
                <table class="t">
                  <thead>
                    <tr>
                      <th>Cluster</th>
                      <th style={{ width: '90px' }}>Verdict</th>
                      <th class="num" style={{ width: '70px' }}>
                        Size
                      </th>
                      <th style={{ width: '100px' }}>Confidence</th>
                      <th style={{ width: '32%' }}>Invariants</th>
                      <th style={{ width: '190px' }}>Active</th>
                      <th style={{ width: '90px' }}>External</th>
                    </tr>
                  </thead>
                  <tbody>
                    {rows.map((x) => (
                      <tr class="clickable cluster-row" aria-selected={selected === x.id} data-c={VERDICT_C[x.verdict] === 'benign' ? undefined : VERDICT_C[x.verdict]} onClick={() => setQuery({ c: x.id }, { replace: false })}>
                        <td title={x.label}>{x.label}</td>
                        <td>
                          <Badge c={VERDICT_C[x.verdict]}>{x.verdict}</Badge>
                        </td>
                        <td class="num">{x.size}</td>
                        <td class="small">
                          {x.confidence} <span class="faint">({x.exactEdges} exact)</span>
                        </td>
                        <td>
                          <div class="inv">
                            {x.invariants.slice(0, 4).map((i) => (
                              <span class="inv-chip">{i}</span>
                            ))}
                          </div>
                        </td>
                        <td class="small mono">
                          {fmtDate(x.firstSeen)} → {fmtDate(x.lastSeen)}
                        </td>
                        <td>{x.external.length ? <Badge c="intel">{x.external.length}</Badge> : <span class="faint">—</span>}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </>
        ) : (
          <>
            <div class="toolbar">
              <span class="small muted">
                <b>Reported association</b>: at least one strong, specific indicator (exact URL, file hash, mailbox, wallet…) is listed in the source’s event. <b>Possible association</b>: only weak overlaps (parent domain, IP, subject, file name). Neither is proof of attribution.
              </span>
            </div>
            <ErrorBox error={external.error} retry={external.reload} />
            {!external.data ? (
              <Loading />
            ) : external.data.length === 0 ? (
              <Empty icon={<Radar />} title="No external associations">
                No synchronised intelligence event (CIRCL, botvrij, OTX, MISP…) lists an indicator from this case. See Intelligence sources for which feeds are current.
              </Empty>
            ) : (
              <div class="table-wrap">
                <table class="t">
                  <thead>
                    <tr>
                      <th style={{ width: '100px' }}>Source</th>
                      <th>Event</th>
                      <th style={{ width: '170px' }}>Assessment</th>
                      <th class="num" style={{ width: '80px' }}>
                        Messages
                      </th>
                      <th style={{ width: '30%' }}>Matched indicators</th>
                    </tr>
                  </thead>
                  <tbody>
                    {external.data.map((x) => (
                      <tr>
                        <td>
                          <Badge c="intel">{x.source}</Badge>
                        </td>
                        <td class="wrap">
                          <b>{x.name}</b>
                          <div class="xs faint">
                            {x.org ?? ''}
                            {x.date ? ` · ${fmtDate(x.date)}` : ''} · {x.eventId}
                          </div>
                          {x.reference && (
                            <div class="xs">
                              <SafeRef url={x.reference} />
                            </div>
                          )}
                          <ul class="rationale" style={{ marginTop: '4px' }}>
                            {x.rationale.map((r) => (
                              <li>{r}</li>
                            ))}
                          </ul>
                        </td>
                        <td>
                          <span class="assess" data-a={x.assessment}>
                            {human(x.assessment)}
                          </span>
                          <div class="xs faint">{x.confidence} confidence</div>
                        </td>
                        <td class="num">{x.messageCount ?? x.messages?.length ?? '—'}</td>
                        <td class="wrap">
                          <div class="row wrap" style={{ gap: '3px' }}>
                            {x.indicators.slice(0, 8).map((i) => (
                              <Badge outline title={`${human(i.matchType)} · strength ${i.strength.toFixed(2)}`}>
                                {i.type}: {short(i.value, 36)}
                              </Badge>
                            ))}
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </>
        )}
      </div>
      {selected && <ClusterDrawer id={selected} onClose={() => setQuery({ c: null })} />}
    </div>
  );
}
