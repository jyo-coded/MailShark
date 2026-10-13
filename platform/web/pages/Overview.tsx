// Case overview: what is in the case, how far processing is, and where the threats are.
import { Boxes, Fingerprint, Upload, AlertOctagon, Radar } from 'lucide-preact';
import { useApi } from '../lib/hooks';
import { navigate } from '../lib/router';
import { fmtBytes, fmtDate, fmtNum, fmtTime, human, plural } from '../lib/format';
import type { CaseStats, Progress } from '../lib/types';
import { useCase } from '../components/Shell';
import { Badge, ClassBadge, DistBar, Empty, ErrorBox, Kpi, Link, Notice, Panel, Sev, Time } from '../components/ui';

export function ProgressPanel({ caseId, compact }: { caseId: string; compact?: boolean }) {
  const p = useApi<Progress>(`/api/cases/${caseId}/progress`, undefined, { poll: 1500 });
  const d = p.data;
  if (!d) return null;
  const m = d.messages;
  const ev = d.evidence;
  const expanding = (ev['stored'] ?? 0) + (ev['expanding'] ?? 0);
  const total = m.total || 1;
  const finished = m.analyzed + m.failed + m.duplicate;
  if (compact && d.done && !d.correlation.pending) return null;
  return (
    <Panel
      title="Processing"
      actions={
        d.done ? (
          <Badge c="ok">Idle</Badge>
        ) : (
          <Badge c="running">
            <span class="spinner" style={{ width: '10px', height: '10px', borderWidth: '1.5px' }} /> Working
          </Badge>
        )
      }
    >
      <div class="progress-block">
        <DistBar
          title="Message processing"
          parts={[
            { c: 'benign', n: m.analyzed },
            { c: 'failed', n: m.failed },
            { c: 'inconclusive', n: m.duplicate },
            { c: 'accent', n: m.running },
            { c: 'pending', n: m.queued },
          ]}
        />
        <div class="stat-line">
          <span>
            <b>{fmtNum(finished)}</b> / {fmtNum(m.total)} messages finished ({Math.round((finished / total) * 100)}%)
          </span>
          <span>
            <b>{fmtNum(m.analyzed)}</b> analysed
          </span>
          <span>
            <b>{fmtNum(m.running)}</b> running
          </span>
          <span>
            <b>{fmtNum(m.queued)}</b> queued
          </span>
          <span style={{ color: m.failed ? 'var(--failed)' : undefined }}>
            <b>{fmtNum(m.failed)}</b> failed
          </span>
          <span>
            <b>{fmtNum(m.duplicate)}</b> duplicates
          </span>
          {expanding > 0 && (
            <span>
              <b>{fmtNum(expanding)}</b> evidence files being unpacked
            </span>
          )}
          {(ev['failed'] ?? 0) > 0 && (
            <span style={{ color: 'var(--failed)' }}>
              <b>{fmtNum(ev['failed'] ?? 0)}</b> evidence files could not be read
            </span>
          )}
        </div>
        <div class="small muted">
          Correlation:{' '}
          {d.correlation.pending ? 'scheduled. It runs once all analyses in the case have finished.' : d.correlation.correlatedAt ? <>up to date (run {d.correlation.version}, <Time ms={d.correlation.correlatedAt} />)</> : 'not run yet.'}
        </div>
      </div>
    </Panel>
  );
}

function Timeline({ t }: { t: NonNullable<CaseStats['timeline']> }) {
  const max = Math.max(1, ...t.buckets.map((b) => b.malicious + b.suspicious + b.other));
  const unit = t.bucketMs <= 3_600_000 ? 'hour' : t.bucketMs <= 21_600_000 ? '6 hours' : t.bucketMs <= 86_400_000 ? 'day' : t.bucketMs <= 604_800_000 ? 'week' : t.bucketMs <= 2_592_000_000 ? '30 days' : 'year';
  return (
    <div>
      <div class="histo" role="img" aria-label="Messages over time">
        {t.buckets.map((b) => (
          <div title={`${fmtTime(b.t, false)} · ${b.malicious} malicious, ${b.suspicious} suspicious, ${b.other} other`}>
            <span data-c="other" style={{ height: `${(b.other / max) * 64}px` }} />
            <span data-c="suspicious" style={{ height: `${(b.suspicious / max) * 64}px` }} />
            <span data-c="malicious" style={{ height: `${(b.malicious / max) * 64}px` }} />
          </div>
        ))}
      </div>
      <div class="row small faint" style={{ marginTop: '6px', justifyContent: 'space-between' }}>
        <span class="mono">{fmtDate(t.start)}</span>
        <span>one bar per {unit} · by Date header (intake time when absent)</span>
        <span class="mono">{fmtDate(t.buckets[t.buckets.length - 1]?.t ?? t.start)}</span>
      </div>
    </div>
  );
}

export function Overview() {
  const { c } = useCase();
  const stats = useApi<CaseStats>(`/api/cases/${c.id}/stats`, undefined, { poll: c.counts.pending > 0 ? 5000 : 30_000 });
  const k = c.counts;
  const base = `/cases/${c.id}`;
  const st = stats.data;
  return (
    <div class="page">
      <div class="page-head">
        <div class="grow">
          <div class="eyebrow">
            Case {c.reference ? <span class="mono">{c.reference}</span> : null} · {c.status} · your role: {c.myRole}
          </div>
          <h1 class="break">{c.name}</h1>
          {c.description && (
            <p class="muted small" style={{ marginTop: '4px', maxWidth: '900px', whiteSpace: 'pre-wrap' }}>
              {c.description}
            </p>
          )}
        </div>
        <div class="actions">
          {c.legalHold && <Badge c="suspicious">Legal hold</Badge>}
          <Badge c={c.onlineLookups ? 'intel' : undefined} outline={!c.onlineLookups} title="Whether investigators may send indicators of this case to third-party lookup services">
            Online lookups {c.onlineLookups ? 'on' : 'off'}
          </Badge>
          {c.myRole !== 'viewer' && c.status === 'open' && (
            <Link class="btn btn-primary" href={`${base}/evidence`}>
              <Upload /> Add evidence
            </Link>
          )}
        </div>
      </div>

      {k.messages === 0 && k.evidence === 0 ? (
        <div class="panel">
          <Empty icon={<Upload />} title="No evidence yet">
            Upload up to 100 files per batch (.eml, .emlx, .mbox or Outlook .msg). Every file is hashed (SHA-256, SHA-1, MD5) and preserved unchanged before analysis.
          </Empty>
        </div>
      ) : (
        <>
          <div class="kpi-strip">
            <Kpi label="Messages" value={fmtNum(k.messages)} sub={`${fmtNum(k.analyzed)} analysed · ${fmtNum(k.evidence)} files (${fmtBytes(k.evidenceBytes)})`} href={`${base}/messages`} />
            <Kpi label="Malicious" value={fmtNum(k.malicious)} c={k.malicious ? 'malicious' : undefined} sub="high-risk score and a strong finding" href={`${base}/messages?class=malicious`} />
            <Kpi label="Suspicious" value={fmtNum(k.suspicious)} c={k.suspicious ? 'suspicious' : undefined} sub="needs analyst review" href={`${base}/messages?class=suspicious`} />
            <Kpi label="Inconclusive · failed" value={`${fmtNum(k.inconclusive)} · ${fmtNum(k.failed)}`} sub="too little evidence · not analysable" href={`${base}/messages?class=inconclusive,failed`} />
            <Kpi label="Intel matches" value={fmtNum(k.withIntel)} c={k.withIntel ? 'intel' : undefined} sub="messages with a listed indicator" href={`${base}/messages?intel=1`} />
            <Kpi label="Campaigns" value={fmtNum(k.threatClusters)} sub={`${plural(k.clusters, 'cluster')} · ${plural(k.externalCampaigns, 'reported association')}`} href={`${base}/campaigns`} />
          </div>
          <ErrorBox error={stats.error} retry={stats.reload} />
          <div class="grid grid-main">
            <div class="col" style={{ gap: 'var(--sp-3)' }}>
              <ProgressPanel caseId={c.id} compact />
              <Panel title="Classification">
                {(['malicious', 'suspicious', 'inconclusive', 'benign', 'failed'] as const).map((cls) => {
                  const n = cls === 'failed' ? k.failed : k[cls];
                  return (
                    <Link class="dist-row" href={`${base}/messages?class=${cls}`}>
                      <ClassBadge c={cls} />
                      <DistBar parts={[{ c: cls, n }, { c: 'none', n: Math.max(0, k.analyzed + k.failed - n) }]} />
                      <span class="n">{fmtNum(n)}</span>
                    </Link>
                  );
                })}
                <p class="small faint" style={{ marginTop: '10px', marginBottom: 0 }}>
                  Classes are produced by documented rules (see <Link href="/docs">Method &amp; limits</Link>). Malicious requires a high score <i>and</i> at least one high-severity finding or an intelligence match; low evidence coverage yields inconclusive rather than benign.
                </p>
              </Panel>
              {st?.timeline && (
                <Panel title="Timeline">
                  <Timeline t={st.timeline} />
                </Panel>
              )}
              <Panel title="Most frequent findings" icon={<AlertOctagon size={15} />} tight>
                {!st ? null : st.topFindings.length === 0 ? (
                  <Empty title="No risk findings">No message in this case produced a finding with positive risk weight.</Empty>
                ) : (
                  <div class="table-wrap">
                    <table class="t compact">
                      <thead>
                        <tr>
                          <th style={{ width: '80px' }}>Severity</th>
                          <th>Finding</th>
                          <th style={{ width: '120px' }}>Category</th>
                          <th class="num" style={{ width: '90px' }}>
                            Messages
                          </th>
                        </tr>
                      </thead>
                      <tbody>
                        {st.topFindings.map((f) => (
                          <tr class="clickable" onClick={() => navigate(`${base}/messages?finding=${encodeURIComponent(f.id)}`)}>
                            <td>
                              <Sev s={f.severity} />
                            </td>
                            <td title={f.id}>{f.title}</td>
                            <td class="muted">{human(f.category)}</td>
                            <td class="num">{fmtNum(f.messages)}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </Panel>
            </div>
            <div class="col" style={{ gap: 'var(--sp-3)' }}>
              <Panel title="Campaign clusters" icon={<Boxes size={15} />} actions={<Link href={`${base}/campaigns`}>All</Link>} tight>
                {!st ? null : st.clusters.length === 0 ? (
                  <Empty title="No clusters">{c.correlatedAt ? 'Correlation found no group of related messages.' : 'Correlation has not run yet.'}</Empty>
                ) : (
                  <table class="t compact">
                    <tbody>
                      {st.clusters.map((cl) => (
                        <tr class="clickable" data-c={cl.verdict === 'threat' ? 'malicious' : cl.verdict === 'mixed' ? 'suspicious' : undefined} onClick={() => navigate(`${base}/campaigns?c=${cl.id}`)}>
                          <td class="trunc" title={cl.label}>
                            {cl.label}
                          </td>
                          <td style={{ width: '70px' }}>
                            <Badge c={cl.verdict === 'threat' ? 'malicious' : cl.verdict === 'mixed' ? 'suspicious' : 'benign'}>{cl.verdict}</Badge>
                          </td>
                          <td class="num" style={{ width: '50px' }}>
                            {cl.size}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
                {st && (st.external['reported-association'] ?? 0) + (st.external['possible-association'] ?? 0) > 0 && (
                  <div class="small muted" style={{ padding: '8px 16px', borderTop: '1px solid var(--line)' }}>
                    External intelligence: {plural(st.external['reported-association'] ?? 0, 'reported association')}, {plural(st.external['possible-association'] ?? 0, 'possible association')}.
                  </div>
                )}
              </Panel>
              <Panel title="Indicators listed by intelligence" icon={<Radar size={15} />} actions={<Link href={`${base}/indicators?intel=1`}>All</Link>} tight>
                {!st ? null : st.topIntel.length === 0 ? (
                  <Empty title="No intelligence matches">None of the case indicators is listed in the synchronised feeds (or the feeds have not been synchronised: see Intelligence sources).</Empty>
                ) : (
                  <table class="t compact">
                    <tbody>
                      {st.topIntel.map((i) => (
                        <tr class="clickable" onClick={() => navigate(`${base}/indicators?i=${i.id}`)}>
                          <td style={{ width: '70px' }} class="faint">
                            {i.type}
                          </td>
                          <td class="mono" title={i.value}>
                            {i.value}
                          </td>
                          <td style={{ width: '110px' }} class="small muted trunc" title={i.sources.join(', ')}>
                            {i.sources.join(', ')}
                          </td>
                          <td class="num" style={{ width: '40px' }}>
                            {i.messages}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </Panel>
              <Panel title="Sender domains" icon={<Fingerprint size={15} />} tight>
                {!st ? null : st.topSenders.length === 0 ? (
                  <Empty title="No senders yet" />
                ) : (
                  <table class="t compact">
                    <thead>
                      <tr>
                        <th>Domain (From header)</th>
                        <th class="num">Threats</th>
                        <th class="num">Total</th>
                      </tr>
                    </thead>
                    <tbody>
                      {st.topSenders.map((s) => (
                        <tr class="clickable" onClick={() => navigate(`${base}/messages?q=${encodeURIComponent('@' + s.domain)}`)}>
                          <td class="mono">{s.domain}</td>
                          <td class="num" style={{ color: s.malicious ? 'var(--malicious)' : s.suspicious ? 'var(--suspicious)' : undefined }}>
                            {s.malicious + s.suspicious}
                          </td>
                          <td class="num">{s.messages}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </Panel>
              {st && st.failures.length > 0 && (
                <Notice c="warn">
                  {plural(st.failures.reduce((s, f) => s + f.n, 0), 'message')} could not be analysed ({st.failures.map((f) => `${f.code ?? 'unknown'} × ${f.n}`).join(', ')}). They are listed with class “failed”; the original evidence is preserved.
                </Notice>
              )}
            </div>
          </div>
        </>
      )}
    </div>
  );
}
