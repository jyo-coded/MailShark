// Message workspace, laid out like a packet analyser: message list on top, analysis tree bottom-left,
// raw message bottom-right. Filters, sort and selection live in the URL; ↑/↓ (or j/k) move the selection.
import { useEffect, useMemo, useRef, useState } from 'preact/hooks';
import { FileText, Inbox, Search, X } from 'lucide-preact';
import { api } from '../lib/api';
import { useApi, useDebounced, useKey, useMediaQuery, useSplitter } from '../lib/hooks';
import { href, navigate, setQuery, useRoute } from '../lib/router';
import { toast, toastError } from '../lib/store';
import { fmtNum, short } from '../lib/format';
import type { MessageList, RawView, Report, MessageDetail } from '../lib/types';
import { useCase } from '../components/Shell';
import { Badge, ClassDot, CLASS_LABEL, Empty, ErrorBox, Loading, Pager, Sev, SortTh, Spinner, Time } from '../components/ui';
import { MessageDetailView } from './MessageDetail';

const CLASS_CHIPS = ['malicious', 'suspicious', 'inconclusive', 'benign', 'failed'] as const;

// ── Raw message pane ─────────────────────────────────────────────────────

/** Which raw lines a component reference points at. */
function linesFor(ref: string, raw: RawView, report: Report | null, lines: { start: number; end: number; text: string }[]): Set<number> {
  const out = new Set<number>();
  const lineOf = (offset: number): number => {
    let lo = 0;
    let hi = lines.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if ((lines[mid] as { start: number }).start <= offset) lo = mid;
      else hi = mid - 1;
    }
    return lo;
  };
  const markRange = (start: number, end: number): void => {
    for (let i = lineOf(start); i < lines.length && (lines[i] as { start: number }).start < Math.max(end, start + 1); i++) out.add(i);
  };
  const header = /^header:(.+)$/.exec(ref);
  if (header) {
    const name = (header[1] as string).replace(/\[\d+\]$/, '').toLowerCase();
    for (const h of raw.headers) {
      const n = h.name.toLowerCase();
      if (name.endsWith('*') ? n.startsWith(name.slice(0, -1)) : n === name) markRange(h.start, h.end);
    }
    return out;
  }
  const search = (needle: string | null | undefined): void => {
    if (!needle || needle.length < 4) return;
    let i = raw.text.indexOf(needle);
    let n = 0;
    while (i >= 0 && n < 50) {
      out.add(lineOf(i));
      i = raw.text.indexOf(needle, i + needle.length);
      n++;
    }
  };
  const link = /^link\[(\d+)\]$/.exec(ref);
  if (link && report) {
    const l = report.links[Number(link[1])];
    search(l?.url);
    if (!out.size) search(l?.host);
    return out;
  }
  const att = /^attachment\[(\d+)\]$/.exec(ref);
  if (att && report) {
    search(report.attachments[Number(att[1])]?.filename);
    return out;
  }
  if (ref.startsWith('body') || ref === 'mime') {
    out.add(lineOf(raw.headerEnd + 1));
    if (ref === 'mime') for (const h of raw.headers) if (h.name.toLowerCase() === 'content-type') markRange(h.start, h.end);
  }
  return out;
}

const MAX_LINES = 6000;

function RawPane({ caseId, messageId, refs, report }: { caseId: string; messageId: string; refs: string[]; report: Report | null }) {
  const raw = useApi<RawView>(`/api/cases/${caseId}/messages/${messageId}/raw`, undefined, { keep: false });
  const [all, setAll] = useState(false);
  const box = useRef<HTMLDivElement>(null);
  const lines = useMemo(() => {
    const t = raw.data?.text ?? '';
    const out: { start: number; end: number; text: string }[] = [];
    let pos = 0;
    while (pos <= t.length) {
      let e = t.indexOf('\n', pos);
      if (e < 0) e = t.length;
      out.push({ start: pos, end: e, text: t.slice(pos, e).replace(/\r$/, '') });
      pos = e + 1;
    }
    return out;
  }, [raw.data]);
  const hl = useMemo(() => {
    const s = new Set<number>();
    if (raw.data) for (const r of refs) for (const i of linesFor(r, raw.data, report, lines)) s.add(i);
    return s;
  }, [refs, raw.data, lines, report]);
  const headerLines = useMemo(() => {
    const s = new Set<number>();
    if (!raw.data) return s;
    for (let i = 0; i < lines.length && (lines[i] as { start: number }).start < raw.data.headerEnd; i++) s.add(i);
    return s;
  }, [raw.data, lines]);
  useEffect(() => {
    if (!hl.size) return;
    const first = Math.min(...hl);
    if (first >= MAX_LINES && !all) setAll(true);
    requestAnimationFrame(() => box.current?.querySelector(`[data-ln="${first}"]`)?.scrollIntoView({ block: 'center' }));
  }, [hl]);
  if (raw.error) return <ErrorBox error={raw.error} retry={raw.reload} />;
  if (!raw.data) return <Loading label="Loading raw message…" />;
  const shown = all ? lines : lines.slice(0, MAX_LINES);
  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', minHeight: 0 }}>
      <div class="toolbar small">
        <b>Raw message</b>
        <span class="muted">
          {fmtNum(raw.data.size)} bytes · {raw.data.encoding}
          {raw.data.truncated ? ' · view truncated (download the evidence for the full bytes)' : ''}
        </span>
        <span class="spacer" />
        {refs.length > 0 && (
          <span class="row" style={{ gap: '4px' }}>
            <span class="faint">highlight:</span>
            {refs.map((r) => (
              <Badge outline>{r}</Badge>
            ))}
            {hl.size === 0 && <span class="faint">(not found verbatim; the content may be encoded)</span>}
          </span>
        )}
      </div>
      <div class="pane" ref={box} style={{ flex: 1, background: 'var(--bg-sunken)' }}>
        <div class="raw" aria-label="Raw message source">
          {shown.map((l, i) => {
            const isHdr = headerLines.has(i);
            const c = isHdr ? l.text.indexOf(':') : -1;
            return (
              <span class="ln" data-ln={i} data-hl={hl.has(i) ? '' : undefined} data-hdr={isHdr && c > 0 && !/^[ \t]/.test(l.text) ? '' : undefined}>
                {isHdr && c > 0 && !/^[ \t]/.test(l.text) ? (
                  <>
                    <span class="hname">{l.text.slice(0, c)}</span>
                    {l.text.slice(c)}
                  </>
                ) : (
                  l.text || ' '
                )}
                {'\n'}
              </span>
            );
          })}
        </div>
        {!all && lines.length > MAX_LINES && (
          <div style={{ padding: '8px 12px' }}>
            <button class="btn btn-sm" onClick={() => setAll(true)}>
              Show all {fmtNum(lines.length)} lines
            </button>
          </div>
        )}
      </div>
    </div>
  );
}

/** Raw pane that knows the report (for link/attachment references) via the shared detail request. */
function RawForMessage({ caseId, messageId, refs }: { caseId: string; messageId: string; refs: string[] }) {
  const d = useApi<MessageDetail>(`/api/cases/${caseId}/messages/${messageId}`, undefined, { keep: false });
  return <RawPane caseId={caseId} messageId={d.data?.analyzedAs ?? messageId} refs={refs} report={d.data?.report ?? null} />;
}

// ── Workspace ────────────────────────────────────────────────────────────

export function Messages() {
  const { c } = useCase();
  const { query } = useRoute();
  const wide = useMediaQuery('(min-width: 1100px)');
  const classes = query.get('class') ?? '';
  const status = query.get('status') ?? '';
  const sort = query.get('sort') ?? 'class';
  const order = (query.get('order') as 'asc' | 'desc' | null) ?? 'desc';
  const page = Number(query.get('page') ?? 0) || 0;
  const selected = query.get('m');
  const [text, setText] = useState(query.get('q') ?? '');
  const q = useDebounced(text, 300);
  useEffect(() => setText(query.get('q') ?? ''), [query.get('q')]);
  useEffect(() => {
    if ((query.get('q') ?? '') !== q) setQuery({ q: q || null, page: null });
  }, [q]);
  const filters = { class: classes, status, q: query.get('q'), sort, order, page, pageSize: 100, intel: query.get('intel'), cluster: query.get('cluster'), finding: query.get('finding'), batch: query.get('batch'), evidence: query.get('evidence'), indicator: query.get('indicator') };
  const list = useApi<MessageList>(`/api/cases/${c.id}/messages`, filters, { poll: c.counts.pending > 0 ? 3000 : false });
  const [refs, setRefs] = useState<string[]>([]);
  const [picked, setPicked] = useState<Set<string>>(new Set());
  useEffect(() => setRefs([]), [selected]);
  const vsplit = useSplitter('messages.v', 'y', 38, 15, 80);
  const hsplit = useSplitter('messages.h', 'x', 60, 30, 80);
  const items = list.data?.items ?? [];
  const tableRef = useRef<HTMLDivElement>(null);

  const facet = (cls: string): number => (list.data?.facets ?? []).filter((f) => (f.class ?? (f.status === 'failed' ? 'failed' : '')) === cls).reduce((s, f) => s + f.n, 0);
  const active = new Set(classes ? classes.split(',') : []);
  const toggleClass = (cls: string): void => {
    const n = new Set(active);
    if (n.has(cls)) n.delete(cls);
    else n.add(cls);
    setQuery({ class: [...n].join(',') || null, page: null });
  };
  const onSort = (col: string): void => setQuery({ sort: col, order: sort === col && order === 'desc' ? 'asc' : 'desc', page: null });
  const select = (id: string): void => setQuery({ m: id });

  useKey(
    (e) => {
      if (!items.length) return;
      const i = items.findIndex((x) => x.id === selected);
      if (e.key === 'ArrowDown' || e.key === 'j') {
        e.preventDefault();
        const n = items[Math.min(items.length - 1, i + 1)];
        if (n) select(n.id);
      } else if (e.key === 'ArrowUp' || e.key === 'k') {
        e.preventDefault();
        const n = items[Math.max(0, i - 1)];
        if (n) select(n.id);
      } else if (e.key === 'Escape' && selected) setQuery({ m: null });
    },
    [items, selected],
  );
  useEffect(() => {
    if (!selected) return;
    tableRef.current?.querySelector(`[data-id="${selected}"]`)?.scrollIntoView({ block: 'nearest' });
  }, [selected, list.data]);

  const extraFilters = (['cluster', 'finding', 'batch', 'evidence', 'indicator', 'intel'] as const).filter((k) => query.get(k));
  const reportSelection = async (): Promise<void> => {
    try {
      const r = await api.post<{ id: string }>(`/api/cases/${c.id}/reports`, { format: 'json', scope: 'messages', messageIds: [...picked] });
      toast('Report generated for the selected messages.', 'success');
      navigate(href(`/cases/${c.id}/reports`, { r: r.id }));
    } catch (e) {
      toastError(e);
    }
  };

  const listPane = (
    <div class="ws-list" style={{ height: '100%' }}>
      <div class="toolbar">
        <div class="input-icon" style={{ flex: '0 1 320px' }}>
          <Search />
          <input class="input" placeholder="Subject, sender, Message-ID, file, SHA-256" value={text} onInput={(e) => setText((e.target as HTMLInputElement).value)} aria-label="Search messages" />
        </div>
        {CLASS_CHIPS.map((cls) => (
          <button class="chip" aria-pressed={active.has(cls)} onClick={() => toggleClass(cls)}>
            <ClassDot c={cls} /> {CLASS_LABEL[cls]} <span class="n">{fmtNum(facet(cls))}</span>
          </button>
        ))}
        <select class="select" value={status} onChange={(e) => setQuery({ status: (e.target as HTMLSelectElement).value || null, page: null })} aria-label="Processing status">
          <option value="">Any status</option>
          <option value="analyzed">Analysed</option>
          <option value="queued,running">Processing</option>
          <option value="failed">Failed</option>
          <option value="duplicate">Duplicates</option>
        </select>
        <button class="chip" aria-pressed={query.get('intel') === '1'} onClick={() => setQuery({ intel: query.get('intel') === '1' ? null : '1', page: null })}>
          Intel matches only
        </button>
        {extraFilters.filter((k) => k !== 'intel').map((k) => (
          <button class="chip" aria-pressed="true" title="Remove this filter" onClick={() => setQuery({ [k]: null, page: null })}>
            {k}: {short(query.get(k), 24)} <X />
          </button>
        ))}
        <span class="spacer" />
        {list.loading && <Spinner />}
        {picked.size > 0 && (
          <>
            <span class="small muted">{picked.size} selected</span>
            <button class="btn btn-sm" onClick={() => void reportSelection()}>
              <FileText /> Report
            </button>
            <button class="btn btn-sm btn-ghost" onClick={() => setPicked(new Set())}>
              Clear
            </button>
          </>
        )}
      </div>
      <ErrorBox error={list.error} retry={list.reload} />
      <div class="table-wrap" ref={tableRef} tabIndex={-1}>
        {!list.data ? (
          <Loading />
        ) : items.length === 0 ? (
          <Empty icon={<Inbox />} title="No messages match">
            {c.counts.messages === 0 ? 'Upload evidence to start.' : 'Change the filters or the search.'}
          </Empty>
        ) : (
          <table class="t">
            <thead>
              <tr>
                <th style={{ width: '30px' }}>
                  <input
                    type="checkbox"
                    aria-label="Select all on this page"
                    checked={items.length > 0 && items.every((i) => picked.has(i.id))}
                    onChange={(e) => {
                      const n = new Set(picked);
                      for (const i of items) (e.target as HTMLInputElement).checked ? n.add(i.id) : n.delete(i.id);
                      setPicked(n);
                    }}
                  />
                </th>
                <SortTh col="class" sort={sort} order={order} onSort={onSort} style={{ width: '118px' }}>
                  Class
                </SortTh>
                <SortTh col="score" sort={sort} order={order} onSort={onSort} num style={{ width: '62px' }}>
                  Score
                </SortTh>
                <th class="hide-sm" style={{ width: '84px' }}>Severity</th>
                <SortTh col="subject" sort={sort} order={order} onSort={onSort}>
                  Subject
                </SortTh>
                <SortTh col="from" sort={sort} order={order} onSort={onSort} class="hide-sm" style={{ width: '22%' }}>
                  From
                </SortTh>
                <SortTh col="sent" sort={sort} order={order} onSort={onSort} class="hide-sm" style={{ width: '158px' }}>
                  Sent (Date header)
                </SortTh>
                <SortTh col="findings" sort={sort} order={order} onSort={onSort} num class="hide-sm" style={{ width: '70px' }}>
                  Find.
                </SortTh>
                <SortTh col="intel" sort={sort} order={order} onSort={onSort} num class="hide-sm" style={{ width: '56px' }}>
                  Intel
                </SortTh>
                <th class="hide-sm" style={{ width: '14%' }}>Campaign</th>
              </tr>
            </thead>
            <tbody>
              {items.map((m) => {
                const cls = m.class ?? (m.status === 'failed' ? 'failed' : null);
                return (
                  <tr class="clickable" data-id={m.id} data-c={cls ?? undefined} aria-selected={selected === m.id} onClick={() => select(m.id)}>
                    <td onClick={(e) => e.stopPropagation()}>
                      <input
                        type="checkbox"
                        aria-label="Select message"
                        checked={picked.has(m.id)}
                        onChange={(e) => {
                          const n = new Set(picked);
                          (e.target as HTMLInputElement).checked ? n.add(m.id) : n.delete(m.id);
                          setPicked(n);
                        }}
                      />
                    </td>
                    <td>
                      <span class="row" style={{ gap: '6px' }}>
                        <ClassDot c={cls ?? m.status} />
                        {cls ? CLASS_LABEL[cls] : m.status}
                      </span>
                    </td>
                    <td class="num">{m.score ?? '—'}</td>
                    <td class="hide-sm">
                      <Sev s={m.severity} />
                    </td>
                    <td title={m.subject ?? ''}>{m.subject || <span class="faint">(no subject)</span>}</td>
                    <td class="mono hide-sm" title={m.fromName ? `${m.fromName} <${m.from}>` : m.from ?? ''}>
                      {m.from ?? '—'}
                    </td>
                    <td class="hide-sm">
                      <Time ms={m.sentAt} />
                    </td>
                    <td class="num hide-sm">{m.findingCount}</td>
                    <td class="num hide-sm" style={{ color: m.intelHits ? 'var(--intel)' : undefined }}>
                      {m.intelHits || ''}
                    </td>
                    <td class="small muted hide-sm" title={m.clusterLabel ?? ''}>
                      {m.clusterLabel ?? ''}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
      {list.data && list.data.total > list.data.pageSize && <Pager page={list.data.page} pageSize={list.data.pageSize} total={list.data.total} onPage={(p) => setQuery({ page: p || null })} />}
    </div>
  );

  if (!selected) return <div class="ws">{listPane}</div>;
  const raw = <RawForMessage caseId={c.id} messageId={selected} refs={refs} />;
  const detail = <MessageDetailView key={selected} caseId={c.id} messageId={selected} onRefs={setRefs} rawTab={!wide} canEdit={c.myRole !== 'viewer'} rawSlot={wide ? null : <div style={{ height: '60vh' }}>{raw}</div>} />;
  return (
    <div class="ws">
      <div class="split split-v" ref={vsplit.ref as never}>
        <div class="pane">{listPane}</div>
        <div class="splitter" role="separator" aria-orientation="horizontal" aria-label="Resize list" onPointerDown={vsplit.onPointerDown as never} />
        {wide ? (
          <div class="split split-h" ref={hsplit.ref as never}>
            <div class="pane">{detail}</div>
            <div class="splitter" role="separator" aria-orientation="vertical" aria-label="Resize raw view" onPointerDown={hsplit.onPointerDown as never} />
            <div class="pane">{raw}</div>
          </div>
        ) : (
          <div class="pane">{detail}</div>
        )}
      </div>
    </div>
  );
}
