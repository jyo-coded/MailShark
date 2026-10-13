// Indicators observed in the case: where each appears, what local intelligence says about it, and
// (only when the case allows it) explicit, audit-logged online lookups.
import type { ComponentChildren } from 'preact';
import { useEffect, useState } from 'preact/hooks';
import { Globe, Search, Waypoints } from 'lucide-preact';
import { api } from '../lib/api';
import { useApi, useDebounced } from '../lib/hooks';
import { href, setQuery, useRoute } from '../lib/router';
import { session } from '../lib/session';
import { toastError, useStore } from '../lib/store';
import { fmtDate, fmtNum, human, plural } from '../lib/format';
import type { IndicatorDetail, IndicatorList, LookupOutcome, SourceInfo } from '../lib/types';
import { useCase } from '../components/Shell';
import { Badge, ClassBadge, Drawer, Empty, ErrorBox, KV, Link, Loading, Mono, Notice, Pager, SafeRef, Time } from '../components/ui';

function Lookups({ d, caseId, onDone }: { d: IndicatorDetail; caseId: string; onDone: () => void }) {
  const { c } = useCase();
  const s = useStore(session);
  const src = useApi<{ sources: SourceInfo[] }>('/api/intel/sources');
  const [busy, setBusy] = useState(false);
  const [results, setResults] = useState<LookupOutcome[] | null>(null);
  const t = d.indicator.type;
  const intelType = t === 'hostname' || t === 'domain' ? 'domain' : t === 'ipv4' || t === 'ipv6' ? 'ip' : t;
  const usable = (src.data?.sources ?? []).filter((x) => x.kind === 'lookup' && x.lookupTypes.includes(intelType as never));
  const [chosen, setChosen] = useState<Set<string>>(new Set());
  if (!s.platform?.onlineLookupsAllowed) return <Notice>Online lookups are disabled on this server.</Notice>;
  if (!c.onlineLookups)
    return (
      <Notice>
        Online lookups are off for this case. A case lead can enable them in <Link href={`/cases/${caseId}/settings`}>case settings</Link>. A lookup sends this indicator to the selected third-party service.
      </Notice>
    );
  if (c.myRole === 'viewer') return <Notice>Viewers cannot run online lookups.</Notice>;
  if (!src.data) return <Loading />;
  if (!usable.length) return <Notice>No configured lookup service supports {t} indicators.</Notice>;
  const run = async (): Promise<void> => {
    setBusy(true);
    try {
      const r = await api.post<{ results: LookupOutcome[] }>(`/api/cases/${caseId}/lookups`, { indicatorId: d.indicator.id, sources: [...chosen] });
      setResults(r.results);
      onDone();
    } catch (e) {
      toastError(e);
    } finally {
      setBusy(false);
    }
  };
  return (
    <div class="col">
      <div class="row wrap">
        {usable.map((x) => (
          <label class="check" title={x.missing.length ? `Needs ${x.missing.join(', ')}` : x.provides}>
            <input
              type="checkbox"
              disabled={x.missing.length > 0 || !x.enabled}
              checked={chosen.has(x.id)}
              onChange={(e) => {
                const n = new Set(chosen);
                (e.target as HTMLInputElement).checked ? n.add(x.id) : n.delete(x.id);
                setChosen(n);
              }}
            />
            {x.name}
            {x.missing.length > 0 && <span class="faint xs">(needs {x.missing.join(', ')})</span>}
          </label>
        ))}
      </div>
      <div class="row">
        <button class="btn btn-sm" disabled={busy || chosen.size === 0} onClick={() => void run()}>
          <Globe /> {busy ? 'Looking up…' : 'Look up online'}
        </button>
        <span class="xs faint">Sends the exact value to the selected services. Recorded in the audit log; results are cached.</span>
      </div>
      {results?.map((r) => (
        <div class="intel-hit">
          <div class="ih-head">
            <Badge c="intel">{r.source}</Badge>
            <Badge c={r.status === 'found' ? 'malicious' : r.status === 'error' ? 'failed' : undefined} outline={r.status !== 'found' && r.status !== 'error'}>
              {r.status}
            </Badge>
            {r.cached && <span class="xs faint">cached result from <Time ms={r.fetchedAt} /></span>}
          </div>
          <div class="small muted" style={{ marginTop: '4px' }}>
            {r.detail}
          </div>
        </div>
      ))}
    </div>
  );
}

function IndicatorDrawer({ id, onClose }: { id: string; onClose: () => void }) {
  const { c } = useCase();
  const d = useApi<IndicatorDetail>(`/api/cases/${c.id}/indicators/${id}`, undefined, { keep: false });
  const x = d.data;
  return (
    <Drawer
      title={x ? <span class="mono">{x.indicator.value}</span> : 'Indicator'}
      sub={x ? `${x.indicator.type} · ${plural(x.observations.length, 'observation')}` : undefined}
      onClose={onClose}
      actions={
        x && (
          <Link class="btn btn-sm" href={href(`/cases/${c.id}/graph`, { focus: `i:${x.indicator.id}` })}>
            <Waypoints /> Graph
          </Link>
        )
      }
    >
      <ErrorBox error={d.error} retry={d.reload} />
      {!x ? (
        <Loading />
      ) : (
        <>
          <KV
            rows={[
              ['Value', <Mono value={x.indicator.value} />],
              ['Type', x.indicator.type],
              ...(x.indicator.registrable ? ([['Registrable domain', <span class="mono">{x.indicator.registrable}</span>]] as [string, ComponentChildren][]) : []),
              ...(x.indicator.registrable ? ([['Popularity (Tranco)', x.indicator.popularityRank ? `rank ${fmtNum(x.indicator.popularityRank)}: listings of popular sites are treated as context only` : 'not in the top list']] as [string, string][]) : []),
              ...(x.indicator.asn ? ([['Network', `AS${x.indicator.asn.asn}${x.indicator.asn.name ? ` · ${x.indicator.asn.name}` : ''}`]] as [string, string][]) : []),
            ]}
          />
          <div>
            <div class="section-title">Where it appears in this case</div>
            <table class="t compact">
              <thead>
                <tr>
                  <th style={{ width: '110px' }}>Class</th>
                  <th>Message</th>
                  <th style={{ width: '120px' }}>Role</th>
                  <th style={{ width: '100px' }}>Component</th>
                </tr>
              </thead>
              <tbody>
                {x.observations.map((o) => (
                  <tr data-c={o.suspicious ? 'suspicious' : undefined}>
                    <td>
                      <ClassBadge c={o.message.class} />
                    </td>
                    <td>
                      <Link href={href(`/cases/${c.id}/messages`, { m: o.message.id })}>{o.message.subject || '(no subject)'}</Link>
                      {o.context && <div class="xs faint trunc">{o.context}</div>}
                    </td>
                    <td class="small">{o.role}</td>
                    <td class="mono xs faint">{o.ref}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div>
            <div class="section-title">Intelligence matches recorded for this case</div>
            {x.caseMatches.length === 0 ? (
              <span class="small faint">No synchronised feed listed this indicator when the case was last correlated.</span>
            ) : (
              x.caseMatches.map((m) => (
                <div class="intel-hit">
                  <div class="ih-head">
                    <Badge c="intel">{m.source}</Badge>
                    <span class="small">
                      {human(m.matchType)}
                      {m.matchedValue !== x.indicator.value ? <> on <span class="mono">{m.matchedValue}</span></> : ''} · strength {m.strength.toFixed(2)}
                    </span>
                    {m.strength === 0 && <Badge outline>context only</Badge>}
                    <span class="xs faint">
                      <Time ms={m.matchedAt} />
                    </span>
                  </div>
                  {m.record && (
                    <div class="small muted" style={{ marginTop: '4px' }}>
                      {[m.record.threat && `threat: ${m.record.threat}`, m.record.family && `family: ${m.record.family}`, m.record.tags && `tags: ${m.record.tags}`, m.record.firstSeen && `first seen ${fmtDate(m.record.firstSeen)}`, m.record.lastSeen && `last seen ${fmtDate(m.record.lastSeen)}`, m.record.suppressed && `context only: ${m.record.suppressed}`].filter(Boolean).join(' · ') || 'no further detail in the feed'}
                      {m.record.reference && (
                        <div>
                          Reference: <SafeRef url={m.record.reference} />
                        </div>
                      )}
                    </div>
                  )}
                </div>
              ))
            )}
          </div>
          <div>
            <div class="section-title">Listings in the current feeds (exact value)</div>
            {x.currentListings.length === 0 ? (
              <span class="small faint">{x.caseMatches.length ? 'The exact value is not listed now; the matches above were made on a related value (host, parent domain) or against an earlier snapshot.' : 'Not listed.'}</span>
            ) : (
              x.currentListings.map((l) => (
                <div class="intel-hit">
                  <div class="ih-head">
                    <Badge c="intel">{l.source}</Badge>
                    <span class="small">
                      {human(l.matchType)}
                      {l.value !== x.indicator.value ? ` (${l.value})` : ''}
                    </span>
                    {l.suppressed && <Badge outline title="Listing kept for context, not counted as a match">context only: {l.suppressed}</Badge>}
                  </div>
                  <div class="small muted" style={{ marginTop: '4px' }}>
                    {[l.threat && `threat: ${l.threat}`, l.family && `family: ${l.family}`, l.tags && `tags: ${l.tags}`, l.firstSeen && `first seen ${fmtDate(l.firstSeen)}`, l.lastSeen && `last seen ${fmtDate(l.lastSeen)}`].filter(Boolean).join(' · ') || 'no further detail in the feed'}
                  </div>
                  {l.reference && (
                    <div class="small">
                      Reference: <SafeRef url={l.reference} />
                    </div>
                  )}
                </div>
              ))
            )}
          </div>
          {x.events.length > 0 && (
            <div>
              <div class="section-title">Intelligence events that list it ({x.events.length})</div>
              <table class="t compact">
                <tbody>
                  {x.events.map((e) => (
                    <tr>
                      <td style={{ width: '90px' }}>
                        <Badge c="intel">{e.source}</Badge>
                      </td>
                      <td class="wrap">
                        <b>{e.name}</b>
                        <div class="xs faint">
                          {e.org ?? ''} {e.date ? `· ${fmtDate(e.date)}` : ''} {e.matchType ? `· ${human(e.matchType)}` : ''} {e.suppressed ? `· context only (${e.suppressed})` : ''}
                        </div>
                      </td>
                      <td style={{ width: '40%' }} class="wrap">
                        <SafeRef url={e.reference} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          <div>
            <div class="section-title">Online lookups</div>
            <Lookups d={x} caseId={c.id} onDone={d.reload} />
            {x.onlineLookups.length > 0 && (
              <table class="t compact" style={{ marginTop: '8px' }}>
                <tbody>
                  {x.onlineLookups.map((l) => (
                    <tr>
                      <td style={{ width: '100px' }}>{l.source}</td>
                      <td style={{ width: '90px' }}>
                        <Badge c={l.status === 'found' ? 'malicious' : undefined} outline={l.status !== 'found'}>
                          {l.status}
                        </Badge>
                      </td>
                      <td>
                        <Time ms={l.fetchedAt} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
          {x.otherCases.length > 0 && (
            <div>
              <div class="section-title">Also seen in your other cases</div>
              {x.otherCases.map((o) => (
                <div class="small">
                  <Link href={`/cases/${o.caseId}`}>{o.caseName}</Link> · {plural(o.messages, 'message')}
                </div>
              ))}
            </div>
          )}
        </>
      )}
    </Drawer>
  );
}

export function Indicators() {
  const { c } = useCase();
  const { query } = useRoute();
  const types = query.get('type') ?? '';
  const sort = query.get('sort') ?? 'messages';
  const page = Number(query.get('page') ?? 0) || 0;
  const selected = query.get('i');
  const [text, setText] = useState(query.get('q') ?? '');
  const q = useDebounced(text, 300);
  useEffect(() => setText(query.get('q') ?? ''), [query.get('q')]);
  useEffect(() => {
    if ((query.get('q') ?? '') !== q) setQuery({ q: q || null, page: null });
  }, [q]);
  const list = useApi<IndicatorList>(`/api/cases/${c.id}/indicators`, { type: types, q: query.get('q'), sort, page, pageSize: 200, intel: query.get('intel') });
  const active = new Set(types ? types.split(',') : []);
  return (
    <div class="ws">
      <div class="toolbar">
        <div class="input-icon" style={{ flex: '0 1 320px' }}>
          <Search />
          <input class="input" placeholder="Search indicator values" value={text} onInput={(e) => setText((e.target as HTMLInputElement).value)} aria-label="Search indicators" />
        </div>
        {(list.data?.types ?? [])
          .sort((a, b) => b.n - a.n)
          .map((t) => (
            <button
              class="chip"
              aria-pressed={active.has(t.type)}
              onClick={() => {
                const n = new Set(active);
                n.has(t.type) ? n.delete(t.type) : n.add(t.type);
                setQuery({ type: [...n].join(',') || null, page: null });
              }}
            >
              {t.type} <span class="n">{fmtNum(t.n)}</span>
            </button>
          ))}
        <button class="chip" aria-pressed={query.get('intel') === '1'} onClick={() => setQuery({ intel: query.get('intel') === '1' ? null : '1', page: null })}>
          Listed by intelligence
        </button>
        <span class="spacer" />
        <select class="select" value={sort} onChange={(e) => setQuery({ sort: (e.target as HTMLSelectElement).value, page: null })} aria-label="Sort">
          <option value="messages">Most messages</option>
          <option value="intel">Intelligence first</option>
          <option value="value">Value A–Z</option>
        </select>
      </div>
      <ErrorBox error={list.error} retry={list.reload} />
      <div class="table-wrap pane" style={{ flex: 1 }}>
        {!list.data ? (
          <Loading />
        ) : list.data.items.length === 0 ? (
          <Empty title="No indicators match" />
        ) : (
          <table class="t">
            <thead>
              <tr>
                <th style={{ width: '90px' }}>Type</th>
                <th>Value</th>
                <th style={{ width: '20%' }}>Roles</th>
                <th class="num" style={{ width: '80px' }}>
                  Messages
                </th>
                <th style={{ width: '18%' }}>Intelligence</th>
                <th style={{ width: '180px' }}>Seen (Date header)</th>
              </tr>
            </thead>
            <tbody>
              {list.data.items.map((i) => (
                <tr class="clickable" aria-selected={selected === String(i.id)} data-c={i.intelHits ? 'malicious' : i.suspicious ? 'suspicious' : undefined} onClick={() => setQuery({ i: i.id }, { replace: false })}>
                  <td class="muted">{i.type}</td>
                  <td class="mono" title={i.value}>
                    {i.value}
                  </td>
                  <td class="small muted" title={i.roles.join(', ')}>
                    {i.roles.join(', ')}
                  </td>
                  <td class="num">{fmtNum(i.messages)}</td>
                  <td>{i.intelSources.length ? <span class="small" style={{ color: 'var(--intel)' }}>{i.intelSources.join(', ')}</span> : <span class="faint">—</span>}</td>
                  <td class="small mono">
                    {fmtDate(i.firstSeen)}
                    {i.lastSeen && i.lastSeen !== i.firstSeen ? ` → ${fmtDate(i.lastSeen)}` : ''}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
      {list.data && list.data.total > list.data.pageSize && <Pager page={list.data.page} pageSize={list.data.pageSize} total={list.data.total} onPage={(p) => setQuery({ page: p || null })} />}
      {selected && <IndicatorDrawer id={selected} onClose={() => setQuery({ i: null })} />}
    </div>
  );
}
