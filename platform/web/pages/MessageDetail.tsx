// Message analysis detail. Three visually separate layers, in the order an analyst reads them:
//   Assessment            the engine's inferences (classification, findings with method and limits)
//   External intelligence what third-party sources report about the message's indicators
//   Observed evidence     facts parsed from the message itself (headers, route, auth, links, files)
// Benign messages get a concise summary first; the full analysis is one click away.
import type { ComponentChildren } from 'preact';
import { useState } from 'preact/hooks';
import { ChevronRight, Eye, FileSearch, Gavel, Globe, Radar, RotateCcw, Waypoints, Link2, Paperclip, Route as RouteIcon, KeyRound, FileCode, Layers, Boxes, History, Fingerprint } from 'lucide-preact';
import { flagLabel, FILE_FLAGS, INTENT_LABELS, LINK_FLAGS } from '../../../extension/src/ui/labels';
import { api } from '../lib/api';
import { useApi } from '../lib/hooks';
import { href, navigate } from '../lib/router';
import { toast, toastError } from '../lib/store';
import { fmtBytes, fmtDuration, fmtNum, human, pct, plural, short } from '../lib/format';
import type { Finding, FindingDoc, MessageDetail, Report } from '../lib/types';
import { Badge, ClassBadge, Empty, ErrorBox, KV, Link, Loading, Mono, Notice, SafeRef, Sev, Tabs, Time } from '../components/ui';

const SEV_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const TONE_C: Record<string, string> = { danger: 'malicious', caution: 'suspicious', info: 'info' };
const METHOD_LABEL: Record<string, string> = { protocol: 'Protocol check', heuristic: 'Heuristic', statistical: 'Statistical', intel: 'Intelligence', correlation: 'Correlation' };

export type DetailTab = 'analysis' | 'indicators' | 'relations' | 'provenance' | 'raw';

function Layer({ kind, icon, title, what, children }: { kind: 'assessed' | 'external' | 'observed'; icon: ComponentChildren; title: string; what: string; children: ComponentChildren }) {
  return (
    <section class="layer" data-layer={kind}>
      <div class="layer-head">
        {icon}
        {title}
        <span class="what">{what}</span>
      </div>
      {children}
    </section>
  );
}

function Sub({ title, icon, children, count }: { title: string; icon?: ComponentChildren; children: ComponentChildren; count?: number }) {
  return (
    <div class="layer-body" style={{ borderTop: '1px solid var(--line)' }}>
      <div class="section-title">
        {icon}
        {title}
        {count !== undefined && <span class="mono faint">{count}</span>}
      </div>
      {children}
    </div>
  );
}

// ── Findings ─────────────────────────────────────────────────────────────

export function FindingItem({ f, doc, onRefs, open: initial = false }: { f: Finding; doc?: FindingDoc; onRefs?: (refs: string[]) => void; open?: boolean }) {
  const [open, setOpen] = useState(initial);
  const trust = f.weight < 0;
  return (
    <div class="finding" data-open={open ? '' : undefined}>
      <div class="finding-head" role="button" tabIndex={0} aria-expanded={open} onClick={() => setOpen(!open)} onKeyDown={(e) => (e.key === 'Enter' || e.key === ' ') && (e.preventDefault(), setOpen(!open))}>
        <ChevronRight class="caret" />
        {trust ? (
          <span class="sev" style={{ color: 'var(--benign)' }}>
            trust
          </span>
        ) : (
          <Sev s={f.severity} />
        )}
        <span class="f-title" title={f.title}>
          {f.title}
        </span>
        <span class="f-meta">
          {doc && <Badge outline>{METHOD_LABEL[doc.method] ?? doc.method}</Badge>}
          <span class="mono xs faint" title="Contribution to the risk score (logit weight)">
            {f.weight > 0 ? '+' : ''}
            {f.weight.toFixed(1)}
          </span>
        </span>
      </div>
      {open && (
        <div class="finding-body">
          <div class="detail break">{f.detail}</div>
          {f.evidence && f.evidence.length > 0 && (
            <>
              <h4>Evidence</h4>
              <table class="ev-table">
                <tbody>
                  {f.evidence.map((e) => (
                    <tr>
                      <td>{e.label}</td>
                      <td class={e.mono ? 'mono' : 'break'}>{e.value}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </>
          )}
          {f.refs && f.refs.length > 0 && (
            <>
              <h4>Affected components</h4>
              <div class="row wrap" style={{ gap: '4px' }}>
                {f.refs.map((r) => (
                  <button class="ref-chip" title="Highlight in the raw message" onClick={() => onRefs?.([r])}>
                    {r}
                  </button>
                ))}
              </div>
            </>
          )}
          {doc && (
            <>
              <h4>Method</h4>
              <div class="muted">
                {METHOD_LABEL[doc.method] ?? doc.method}. {doc.rationale}
              </div>
              <h4>Limitations</h4>
              <div class="muted">{doc.limitations}</div>
              {doc.actions.length > 0 && (
                <>
                  <h4>Recommended actions</h4>
                  <ul>
                    {doc.actions.map((a) => (
                      <li>{a}</li>
                    ))}
                  </ul>
                </>
              )}
              {doc.attack && doc.attack.length > 0 && (
                <>
                  <h4>MITRE ATT&amp;CK</h4>
                  <div class="row wrap" style={{ gap: '4px' }}>
                    {doc.attack.map((t) => (
                      <a class="badge outline" href={`https://attack.mitre.org/techniques/${t.id.replace('.', '/')}/`} target="_blank" rel="noopener noreferrer">
                        {t.id} · {t.name}
                      </a>
                    ))}
                  </div>
                </>
              )}
            </>
          )}
          <div class="mono xs faint">finding id: {f.id}</div>
        </div>
      )}
    </div>
  );
}

function sortFindings(fs: Finding[]): Finding[] {
  return [...fs].sort((a, b) => (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9) || b.weight - a.weight);
}

// ── Observed evidence sections ───────────────────────────────────────────

function AuthSection({ r }: { r: Report }) {
  const a = r.auth;
  const cell = (m: string, v: string | null, s?: string | null) => (
    <div class="auth-cell">
      <div class="m">{m}</div>
      <div class="r" data-r={v ?? 'unknown'}>
        {v ?? 'n/a'}
      </div>
      {s && <div class="s">{s}</div>}
    </div>
  );
  return (
    <>
      {a.source === 'none' ? (
        <Notice>No Authentication-Results header from a receiving server. SPF/DKIM/DMARC status is <b>unknown</b>, which is not the same as failed (common for exported or forwarded copies).</Notice>
      ) : a.source === 'topmost' ? (
        <Notice c="warn">
          Results taken from the top-most Authentication-Results header (<span class="mono">{a.authServId ?? 'no authserv-id'}</span>), which could not be attributed to the receiving provider. They are given reduced weight because a sender can forge such headers.
        </Notice>
      ) : (
        <div class="small muted" style={{ marginBottom: '8px' }}>
          Recorded by the receiving server <span class="mono">{a.authServId}</span>.
        </div>
      )}
      {a.source !== 'none' && (
        <div class="auth-grid">
          {cell('SPF', a.spf, a.spfDomain ? `${a.spfDomain}${a.spfAligned === false ? ' (not aligned)' : a.spfAligned ? ' (aligned)' : ''}` : null)}
          {cell('DKIM', a.dkim, a.dkimDomains.length ? `${a.dkimDomains.join(', ')}${a.dkimAligned === false ? ' (not aligned)' : a.dkimAligned ? ' (aligned)' : ''}` : null)}
          {cell('DMARC', a.dmarc, a.dmarcPolicy ? `policy ${a.dmarcPolicy}` : a.headerFrom)}
          {cell('ARC', a.arc)}
          {cell('CompAuth', a.compauth)}
        </div>
      )}
      {r.dkim && r.dkim.length > 0 && (
        <div style={{ marginTop: '12px' }}>
          <div class="section-title">DKIM signatures verified by the platform</div>
          <div class="table-wrap">
            <table class="t compact">
              <thead>
                <tr>
                  <th>Domain · selector</th>
                  <th style={{ width: '90px' }}>Body hash</th>
                  <th style={{ width: '120px' }}>Signature</th>
                  <th style={{ width: '70px' }}>Key</th>
                  <th>Notes</th>
                </tr>
              </thead>
              <tbody>
                {r.dkim.map((d) => (
                  <tr data-c={d.bodyHash === 'fail' || d.signature === 'fail' ? 'malicious' : undefined}>
                    <td class="mono" title={d.signedHeaders.join(', ')}>
                      {d.domain} · {d.selector}
                    </td>
                    <td>
                      <Badge c={d.bodyHash === 'pass' ? 'ok' : d.bodyHash === 'fail' ? 'malicious' : undefined} outline={d.bodyHash !== 'pass' && d.bodyHash !== 'fail'}>
                        {d.bodyHash}
                      </Badge>
                    </td>
                    <td>
                      <Badge c={d.signature === 'pass' ? 'ok' : d.signature === 'fail' ? 'malicious' : undefined} outline={d.signature !== 'pass' && d.signature !== 'fail'}>
                        {d.signature}
                      </Badge>
                    </td>
                    <td class="mono small">{d.keyBits ? `${d.keyBits}b` : '—'}</td>
                    <td class="wrap small muted">
                      {d.algorithm} · {d.canonicalization}
                      {d.coversFrom ? '' : ' · does not sign From'}
                      {d.bodyLengthLimit !== null ? ` · l=${d.bodyLengthLimit}${d.bodyBeyondLimit ? ' (content appended after signing)' : ''}` : ''}
                      {d.expiredAtReceipt ? ' · expired at receipt' : ''}
                      {d.keyTesting ? ' · key in testing mode' : ''}
                      {d.detail ? ` · ${d.detail}` : ''}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div class="xs faint" style={{ marginTop: '4px' }}>
            Body hashes are checked offline against the evidence. Header signatures need the signer’s public key over DNS (only when the case allows online lookups) and are checked against the key published today, which may differ from the key used when the message was sent.
          </div>
        </div>
      )}
    </>
  );
}

function RouteSection({ r }: { r: Report }) {
  const hops = r.route.hops;
  const fx = r.forensics;
  return (
    <>
      {hops.length === 0 ? (
        <span class="small faint">No Received headers: the delivery path is not recorded in this copy.</span>
      ) : (
        <ol class="hops">
          {hops.map((h) => (
            <li data-trusted={h.trusted ? '' : undefined} data-origin={h.fromIp && h.fromIp === r.route.originIp ? '' : undefined}>
              <div class="h-main">
                <span class="mono">{h.fromHost ?? h.fromRdns ?? '?'}</span>
                {h.fromIp && <span class="mono muted">[{h.fromIp}]</span>}
                <span class="faint">→</span>
                <span class="mono">{h.byHost ?? '?'}</span>
                {h.fromIp && h.fromIp === r.route.originIp && <Badge c="suspicious">origin</Badge>}
                {h.trusted && <Badge c="ok" title="Written by the recipient's own infrastructure">receiver</Badge>}
              </div>
              <div class="h-sub">
                <Time ms={h.timestamp} />
                {h.delaySec !== null ? ` · +${fmtDuration(h.delaySec)}` : ''}
                {h.protocol ? ` · ${h.protocol}` : ''}
                {h.tls ? ` · ${h.tls}` : ''}
                {h.fromRdns && h.fromRdns !== h.fromHost ? ` · rDNS ${h.fromRdns}` : ''}
              </div>
            </li>
          ))}
        </ol>
      )}
      <div style={{ marginTop: '8px' }}>
        <KV
          rows={[
            ['Origin', r.route.originIp ? <span class="mono">{`${r.route.originIp}${r.route.originHost ? ` (${r.route.originHost})` : ''}${r.route.originOrg ? ` · ${r.route.originOrg}` : ''}`}</span> : 'not determined'],
            ['Transit', fmtDuration(r.route.totalTransitSec)],
            ['Date header skew', r.route.dateSkewSec === null ? '—' : fmtDuration(r.route.dateSkewSec)],
            ...(fx?.originating.clientIp ? ([['Submitting client', <span class="mono">{`${fx.originating.clientIp} (${fx.originating.clientIpHeader ?? ''})`}</span>]] as [string, ComponentChildren][]) : []),
            ...(fx?.originating.authenticatedSender ? ([['Authenticated account', <span class="mono">{fx.originating.authenticatedSender}</span>]] as [string, ComponentChildren][]) : []),
            ...(fx?.originating.sendingScript ? ([['Sending script', <span class="mono">{`${fx.originating.sendingScript} (${fx.originating.scriptHeader ?? ''})`}</span>]] as [string, ComponentChildren][]) : []),
            ...(fx?.originating.hostingServer ? ([['Hosting server', <span class="mono">{fx.originating.hostingServer}</span>]] as [string, ComponentChildren][]) : []),
            ...(fx?.heloMismatch ? ([['HELO', <span class="mono">{`${fx.heloMismatch.helo} from ${fx.heloMismatch.ip}${fx.heloMismatch.rdns ? ` (rDNS ${fx.heloMismatch.rdns})` : ''}`}</span>]] as [string, ComponentChildren][]) : []),
            ...(fx && fx.timestampAnomalies.length ? ([['Timeline anomalies', fx.timestampAnomalies.map((t) => `hop ${t.fromHop}→${t.toHop}: ${fmtDuration(t.deltaSec)}${t.involvesUnverifiedHop ? ' (unverified hop)' : ''}`).join('; ')]] as [string, ComponentChildren][]) : []),
            ...(fx && fx.injectedAuthResults.length ? ([['Injected verdict headers', fx.injectedAuthResults.map((x) => `${x.authServId}: ${x.reason}`).join('; ')]] as [string, ComponentChildren][]) : []),
            ['Message-ID domain', fx?.messageIdDomain ? <span class="mono">{`${fx.messageIdDomain}${fx.messageIdMatchesFrom === false ? ' (differs from From)' : ''}`}</span> : '—'],
          ]}
        />
      </div>
    </>
  );
}

function LinksSection({ r }: { r: Report }) {
  if (!r.links.length) return <span class="small faint">No links.</span>;
  return (
    <div class="table-wrap">
      <table class="t compact">
        <thead>
          <tr>
            <th style={{ width: '40px' }}>#</th>
            <th>URL (not clickable)</th>
            <th style={{ width: '30%' }}>Signals</th>
          </tr>
        </thead>
        <tbody>
          {r.links.map((l, i) => (
            <tr data-c={l.risk >= 3 ? 'malicious' : l.risk === 2 ? 'suspicious' : undefined}>
              <td class="num faint">{i}</td>
              <td class="wrap">
                <Mono value={l.url} max={160} />
                <div class="xs faint">
                  {l.sources.join(', ')}
                  {l.displayText ? ` · shown as “${l.displayText.slice(0, 80)}”` : ''}
                  {l.unwrappedFrom ? ' · unwrapped from a tracking/redirect link' : ''}
                  {l.unicodeHost ? ` · Unicode host ${l.unicodeHost}` : ''}
                </div>
              </td>
              <td class="wrap">
                <div class="row wrap" style={{ gap: '3px' }}>
                  {l.intelHit && <Badge c="intel">Listed: {l.intelHit}</Badge>}
                  {l.lookalikeOf && <Badge c="malicious">Look-alike of {l.lookalikeOf}</Badge>}
                  {l.flags.map((f) => {
                    const [label, tone] = flagLabel(LINK_FLAGS, f);
                    return (
                      <Badge c={tone ? TONE_C[tone] : undefined} outline={!tone} title={f}>
                        {label}
                      </Badge>
                    );
                  })}
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function AttachmentsSection({ r }: { r: Report }) {
  if (!r.attachments.length) return <span class="small faint">No attachments.</span>;
  return (
    <div class="col">
      {r.attachments.map((a, i) => (
        <div class="panel" style={{ padding: '10px 12px', borderColor: a.risk >= 3 ? 'var(--malicious)' : a.risk === 2 ? 'var(--suspicious)' : undefined }}>
          <div class="row wrap">
            <Paperclip size={14} />
            <b class="break">{a.filename || '(unnamed)'}</b>
            <span class="faint small">attachment[{i}]</span>
            <span class="spacer" />
            {a.flags.map((f) => {
              const [label, tone] = flagLabel(FILE_FLAGS, f);
              return (
                <Badge c={tone ? TONE_C[tone] : undefined} outline={!tone} title={f}>
                  {label}
                </Badge>
              );
            })}
          </div>
          <div style={{ marginTop: '6px' }}>
            <KV
              rows={[
                ['Type', `${a.detectedType} (declared ${a.declaredType}${a.extension ? `, extension .${a.extension}` : ''})`],
                ['Size · entropy', `${fmtBytes(a.size)} · ${a.entropy.toFixed(2)} bits/byte${a.inline ? ' · inline' : ''}`],
                ['SHA-256', <Mono value={a.sha256} />],
                ['MD5', <Mono value={a.md5} />],
                ...(a.entries.length ? ([['Archive entries', a.entries.slice(0, 30).map((e) => `${e.name}${e.encrypted ? ' (encrypted)' : ''}`).join(', ') + (a.entries.length > 30 ? ` … (+${a.entries.length - 30})` : '')]] as [string, string][]) : []),
                ...(a.urls.length ? ([['Links inside', a.urls.slice(0, 10).join('  ')]] as [string, string][]) : []),
                ...(a.qr ? ([['QR code decodes to', <Mono value={a.qr} />]] as [string, ComponentChildren][]) : []),
              ]}
            />
          </div>
        </div>
      ))}
      <div class="xs faint">Attachments are parsed statically from the stored bytes. They are never opened, rendered or executed.</div>
    </div>
  );
}

function ContentSection({ r }: { r: Report }) {
  const c = r.content;
  const h = r.html;
  return (
    <>
      <KV
        rows={[
          ['Language', c.language || '—'],
          ['Primary intent', c.intent ? INTENT_LABELS[c.intent] ?? human(c.intent) : 'none detected'],
          ['Intent signals', c.intents.length ? c.intents.map((x) => `${x.label} (${x.score.toFixed(1)}: ${x.matches.slice(0, 4).join(', ')})`).join('; ') : '—'],
          ['Urgency', ['none', 'mild', 'strong', 'extreme'][c.urgency] ?? String(c.urgency)],
          ['Requested actions', c.requestedActions.length ? c.requestedActions.join(', ') : '—'],
          ['Brands mentioned', c.brandMentions.length ? c.brandMentions.join(', ') : '—'],
          ['Phone numbers', c.phoneNumbers.length ? <span class="mono">{c.phoneNumbers.join(', ')}</span> : '—'],
          ['Crypto wallets', c.wallets?.length ? <span class="mono break">{c.wallets.join(', ')}</span> : '—'],
          ['Other cues', [c.genericGreeting && 'generic greeting', c.fakeReply && 'fake “Re:”', c.subjectHomoglyph && 'look-alike characters in subject', c.splitWords && 'split words', c.personalized && `personalised with ${c.personalized}`].filter(Boolean).join(', ') || '—'],
          [
            'HTML',
            h.present
              ? `${fmtNum(h.tagCount)} tags · ${h.forms.length} forms${h.forms.some((f) => f.hasPassword) ? ' (password field)' : ''} · ${h.scripts} scripts · ${h.iframes} iframes · ${h.trackingPixels} tracking pixels${h.hiddenTextChars ? ` · ${fmtNum(h.hiddenTextChars)} hidden characters` : ''}${h.zeroWidthChars ? ` · ${h.zeroWidthChars} zero-width characters` : ''}${h.imageOnly ? ' · image only' : ''}${h.metaRefresh ? ` · meta refresh to ${h.metaRefresh}` : ''}`
              : 'no HTML part',
          ],
        ]}
      />
      {c.textPreview && (
        <div style={{ marginTop: '10px' }}>
          <div class="section-title">Text preview (untrusted content, shown as plain text)</div>
          <pre class="mono small" style={{ whiteSpace: 'pre-wrap', margin: 0, maxHeight: '220px', overflow: 'auto', padding: '8px', background: 'var(--bg-sunken)', borderRadius: 'var(--r-md)', border: '1px solid var(--line)' }}>
            {c.textPreview}
          </pre>
        </div>
      )}
    </>
  );
}

function StructureSection({ r }: { r: Report }) {
  const s = r.structure;
  return (
    <>
      <KV
        rows={[
          ['MIME parts', `${s.partCount} (max depth ${s.maxDepth})`],
          ['Text / HTML', `${s.hasText ? 'text' : 'no text'} · ${s.hasHtml ? 'HTML' : 'no HTML'}${s.textHtmlDivergence !== null ? ` · divergence ${pct(s.textHtmlDivergence)}` : ''}`],
          ['Duplicate headers', s.duplicateHeaders.length ? s.duplicateHeaders.join(', ') : '—'],
          ['Anomalies', s.anomalies.length ? s.anomalies.join('; ') : '—'],
          ['Bulk sender (ESP)', r.esp ? `${r.esp.name}${r.esp.campaignId ? ` · campaign ${r.esp.campaignId}` : ''} (${r.esp.evidence})` : '—'],
        ]}
      />
      <table class="t compact" style={{ marginTop: '8px' }}>
        <tbody>
          {s.parts.map((p) => (
            <tr>
              <td class="mono" style={{ paddingLeft: `${10 + p.depth * 14}px` }}>
                {p.contentType}
              </td>
              <td class="small muted" style={{ width: '30%' }}>
                {[p.encoding, p.charset, p.filename].filter(Boolean).join(' · ')}
              </td>
              <td class="num" style={{ width: '80px' }}>
                {fmtBytes(p.size)}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
  );
}

function CoverageSection({ r }: { r: Report }) {
  if (!r.coverage) return null;
  return (
    <>
      <div class="coverage">
        {r.coverage.layers.map((l) => (
          <div class="cov" data-s={l.status} title={l.note}>
            <div class="l">{l.label}</div>
            <div class="st">{l.status}</div>
          </div>
        ))}
      </div>
      <div class="xs faint" style={{ marginTop: '6px' }}>
        Evidence coverage {pct(r.coverage.score)}: the share of applicable evidence layers present in this copy. Low coverage lowers confidence and can make a message inconclusive instead of benign.
      </div>
    </>
  );
}

function HeadersSection({ r }: { r: Report }) {
  const s = r.sender;
  const addr = (a: { name: string; address: string } | null) => (a ? (a.name ? `${a.name} <${a.address}>` : a.address) : null);
  return (
    <KV
      rows={[
        ['From', <span class="mono break">{addr(s.from) ?? '—'}</span>],
        ['Reply-To', s.replyTo.length ? <span class="mono break">{s.replyTo.map(addr).join(', ')}</span> : '—'],
        ['Return-Path', <span class="mono break">{addr(s.returnPath) ?? '—'}</span>],
        ['Sender', <span class="mono break">{addr(s.sender) ?? '—'}</span>],
        ['To', <span class="mono break">{r.summary.to.map(addr).join(', ') || '—'}</span>],
        ['Subject', <span class="break">{r.summary.subject || '(none)'}</span>],
        ['Date', r.summary.date ?? '—'],
        ['Message-ID', <span class="mono break">{r.summary.messageId ?? '—'}</span>],
        ['Sender assessment', [s.isFreemail && 'free-mail provider', s.impersonatedBrand && `claims to be ${s.impersonatedBrand}`, s.verifiedBrand && `verified as ${s.verifiedBrand}`, s.lookalikeOf && `${s.lookalikeKind} look-alike of ${s.lookalikeOf}`, s.displayNameAddress && `address in display name (${s.displayNameAddress})`, s.roleName && `role name “${s.roleName}”`].filter(Boolean).join(' · ') || '—'],
      ]}
    />
  );
}

// ── Main view ────────────────────────────────────────────────────────────

export function MessageDetailView({ caseId, messageId, onRefs, rawTab, canEdit, rawSlot }: { caseId: string; messageId: string; onRefs: (refs: string[]) => void; rawTab: boolean; canEdit: boolean; rawSlot: ComponentChildren }) {
  const d = useApi<MessageDetail>(`/api/cases/${caseId}/messages/${messageId}`, undefined, { keep: false });
  const [tab, setTab] = useState<DetailTab>('analysis');
  const [full, setFull] = useState(false);
  const data = d.data;
  if (d.error) return <ErrorBox error={d.error} retry={d.reload} />;
  if (!data) return <Loading />;
  const m = data.message;
  const r = data.report;
  const refs = (x: string[]): void => {
    onRefs(x);
    if (rawTab) setTab('raw');
  };
  const reanalyze = async (): Promise<void> => {
    try {
      await api.post(`/api/cases/${caseId}/messages/${messageId}/reanalyze`);
      toast('Queued for re-analysis with the current engine and intelligence snapshot.', 'success');
      setTimeout(d.reload, 1500);
    } catch (e) {
      toastError(e);
    }
  };
  const cls = m.class ?? (m.status === 'duplicate' ? null : m.status === 'failed' ? 'failed' : null);
  const findings = r ? sortFindings(r.findings) : [];
  const risk = findings.filter((f) => f.weight > 0 && f.category !== 'integrity');
  const trust = findings.filter((f) => f.weight < 0);
  const integrity = findings.filter((f) => f.category === 'integrity');
  const neutral = findings.filter((f) => f.weight === 0 && f.category !== 'integrity');
  const concise = r && r.classification?.class === 'benign' && !full;

  return (
    <div class="ws-detail" style={{ height: '100%' }}>
      <div class="verdict" data-c={cls ?? undefined}>
        <div class="v-score" title={`Risk score ${m.score ?? '—'} / 100`}>
          {m.score ?? '—'}
        </div>
        <div style={{ minWidth: 0 }}>
          <div class="v-title">{m.subject || '(no subject)'}</div>
          <div class="v-sub">
            {m.fromName ? `${m.fromName} <${m.from ?? ''}>` : m.from ?? 'unknown sender'} → {m.to ?? '—'} · <Time ms={m.sentAt} />
          </div>
          {r && <div class="v-sub" style={{ marginTop: '2px' }}>{r.oneLiner}</div>}
        </div>
        <div class="v-badges">
          <ClassBadge c={cls} />
          {m.severity && m.severity !== 'none' && (
            <Badge c={m.severity} title="Highest severity among the message's findings">
              {m.severity}
            </Badge>
          )}
          {m.confidence && (
            <Badge outline title="Confidence in the classification (see Method & limits)">
              {m.confidence} confidence
            </Badge>
          )}
          {m.intelHits > 0 && <Badge c="intel">{plural(m.intelHits, 'intel match', 'intel matches')}</Badge>}
          <Link class="btn btn-sm" href={href(`/cases/${caseId}/graph`, { focus: `m:${data.analyzedAs ?? m.id}` })} title="Open this message's neighbourhood in the graph">
            <Waypoints /> Graph
          </Link>
          {canEdit && m.status !== 'duplicate' && (
            <button class="btn btn-sm" onClick={() => void reanalyze()} title="Analyse again with the current engine and intelligence (the previous result is replaced; the evidence is unchanged)">
              <RotateCcw /> Re-analyse
            </button>
          )}
        </div>
      </div>
      <Tabs<DetailTab>
        value={tab}
        onChange={setTab}
        tabs={[
          { id: 'analysis', label: 'Analysis' },
          { id: 'indicators', label: 'Indicators', count: r?.iocs?.length ?? null },
          { id: 'relations', label: 'Relations', count: data.related.length + data.externalCampaigns.length || null },
          { id: 'provenance', label: 'Provenance' },
          { id: 'raw', label: 'Raw', hidden: !rawTab },
        ]}
      />
      <div class="detail-scroll">
        {data.analyzedAs && (
          <div style={{ padding: '12px 16px 0' }}>
            <Notice>
              This message is byte-identical to another message in the case; the analysis shown is that of the first copy (<span class="mono">{short(data.analyzedAs, 20)}</span>).
            </Notice>
          </div>
        )}
        {tab === 'raw' && rawSlot}
        {tab === 'analysis' &&
          (m.status === 'failed' && !r ? (
            <div style={{ padding: '16px' }}>
              <Notice c="danger">
                Analysis failed: {m.error?.detail ?? 'unknown error'} (<span class="mono">{m.error?.code ?? 'error'}</span>). The original evidence is preserved and unchanged.{canEdit ? ' You can retry with Re-analyse.' : ''}
              </Notice>
            </div>
          ) : !r ? (
            <Empty title={m.status === 'duplicate' ? 'Duplicate' : 'Not analysed yet'}>Status: {m.status}. This view refreshes when the analysis is stored.</Empty>
          ) : concise ? (
            <div class="summary-benign">
              <Notice>
                <b>Benign, {r.classification?.confidence} confidence.</b> {r.classification?.rationale.join(' ')}
              </Notice>
              <KV
                rows={[
                  ['Authentication', r.auth.source === 'none' ? 'not recorded in this copy (unknown, not failed)' : `SPF ${r.auth.spf} · DKIM ${r.auth.dkim} · DMARC ${r.auth.dmarc}${r.auth.source === 'topmost' ? ' (unattributed results)' : ''}`],
                  ['Links · attachments', `${r.links.length} · ${r.attachments.length}`],
                  ['Risk findings', risk.length ? risk.map((f) => f.title).join('; ') : 'none'],
                  ['Trust signals', trust.length ? trust.map((f) => f.title).join('; ') : 'none'],
                  ['Evidence coverage', r.coverage ? pct(r.coverage.score) : '—'],
                ]}
              />
              <div>
                <button class="btn btn-sm" onClick={() => setFull(true)}>
                  <Eye /> Show full analysis
                </button>
              </div>
            </div>
          ) : (
            <>
              <Layer kind="assessed" icon={<Gavel />} title="Assessment" what="engine inferences: reproducible from the evidence, engine version and thresholds">
                <div class="layer-body">
                  {r.classification && (
                    <ul class="rationale">
                      {r.classification.rationale.map((x) => (
                        <li>{x}</li>
                      ))}
                    </ul>
                  )}
                </div>
                {risk.length === 0 ? (
                  <div class="layer-body small faint">No risk findings.</div>
                ) : (
                  <div class="tree">
                    {risk.map((f, i) => (
                      <FindingItem f={f} doc={data.findingDocs[f.id]} onRefs={refs} open={i === 0 && (SEV_ORDER[f.severity] ?? 9) <= 1} />
                    ))}
                  </div>
                )}
                {trust.length > 0 && (
                  <Sub title="Trust signals (lower the score)" count={trust.length}>
                    <div class="tree" style={{ margin: '0 -16px' }}>
                      {trust.map((f) => (
                        <FindingItem f={f} doc={data.findingDocs[f.id]} onRefs={refs} />
                      ))}
                    </div>
                  </Sub>
                )}
                {neutral.length > 0 && (
                  <Sub title="Informational" count={neutral.length}>
                    <div class="tree" style={{ margin: '0 -16px' }}>
                      {neutral.map((f) => (
                        <FindingItem f={f} doc={data.findingDocs[f.id]} onRefs={refs} />
                      ))}
                    </div>
                  </Sub>
                )}
                {integrity.length > 0 && (
                  <Sub title="Evidence integrity observations (reported, never scored)" count={integrity.length}>
                    <div class="tree" style={{ margin: '0 -16px' }}>
                      {integrity.map((f) => (
                        <FindingItem f={f} doc={data.findingDocs[f.id]} onRefs={refs} />
                      ))}
                    </div>
                  </Sub>
                )}
                {data.cluster && (
                  <Sub title="Campaign correlation (inference)" icon={<Boxes size={13} />}>
                    <div class="small">
                      Member of local cluster{' '}
                      <Link href={href(`/cases/${caseId}/campaigns`, { c: data.cluster.id })}>
                        <b>{data.cluster.label}</b>
                      </Link>{' '}
                      ({data.cluster.size} messages, {data.cluster.confidence} confidence, {data.cluster.verdict}). See the Relations tab for the shared evidence.
                    </div>
                  </Sub>
                )}
              </Layer>
              <Layer kind="external" icon={<Radar />} title="External intelligence" what="what third-party sources report; not observed in the message">
                <div class="layer-body">
                  {data.intel.length === 0 && data.externalCampaigns.length === 0 ? (
                    <span class="small faint">No indicator of this message is listed in the synchronised intelligence (snapshot {short(data.processing?.intelSnapshot ?? null, 12)}).</span>
                  ) : (
                    <>
                      {data.intel.map((x) => (
                        <div class="intel-hit">
                          <div class="ih-head">
                            <Badge c="intel">{x.source}</Badge>
                            <span class="mono break">{x.indicator}</span>
                            <span class="faint small">
                              {x.indicatorType} · {human(x.matchType)}
                              {x.matchedValue !== x.indicator ? ` (${x.matchedValue})` : ''} · strength {x.strength.toFixed(2)}
                            </span>
                          </div>
                          {x.record && (
                            <div class="small muted" style={{ marginTop: '4px' }}>
                              {[x.record.threat && `threat: ${x.record.threat}`, x.record.family && `family: ${x.record.family}`, x.record.tags && `tags: ${x.record.tags}`, x.record.firstSeen && `first seen ${new Date(x.record.firstSeen).toISOString().slice(0, 10)}`, x.record.lastSeen && `last seen ${new Date(x.record.lastSeen).toISOString().slice(0, 10)}`, x.record.suppressed && `context only: ${x.record.suppressed}`].filter(Boolean).join(' · ')}
                              {x.record.reference && (
                                <div>
                                  Reference: <SafeRef url={x.record.reference} />
                                </div>
                              )}
                            </div>
                          )}
                        </div>
                      ))}
                      {data.externalCampaigns.map((x) => (
                        <div class="intel-hit">
                          <div class="ih-head">
                            <Badge c="intel">{x.source}</Badge>
                            <b class="break">{x.name}</b>
                            <span class="assess" data-a={x.assessment}>
                              {x.assessment === 'reported-association' ? 'Reported association' : 'Possible association'}
                            </span>
                            <Badge outline>{x.confidence} confidence</Badge>
                          </div>
                          <ul class="rationale" style={{ marginTop: '4px' }}>
                            {x.rationale.map((y) => (
                              <li>{y}</li>
                            ))}
                          </ul>
                          {x.reference && (
                            <div class="small">
                              Reference: <SafeRef url={x.reference} />
                            </div>
                          )}
                        </div>
                      ))}
                    </>
                  )}
                </div>
              </Layer>
              <Layer kind="observed" icon={<FileSearch />} title="Observed evidence" what="facts parsed from this message’s bytes">
                <Sub title="Header identity" icon={<Fingerprint size={13} />}>
                  <HeadersSection r={r} />
                </Sub>
                <Sub title="Authentication" icon={<KeyRound size={13} />}>
                  <AuthSection r={r} />
                </Sub>
                <Sub title="Delivery route (oldest hop first)" icon={<RouteIcon size={13} />} count={r.route.hops.length}>
                  <RouteSection r={r} />
                </Sub>
                <Sub title="Links" icon={<Link2 size={13} />} count={r.links.length}>
                  <LinksSection r={r} />
                </Sub>
                <Sub title="Attachments" icon={<Paperclip size={13} />} count={r.attachments.length}>
                  <AttachmentsSection r={r} />
                </Sub>
                <Sub title="Content and HTML" icon={<FileCode size={13} />}>
                  <ContentSection r={r} />
                </Sub>
                <Sub title="MIME structure" icon={<Layers size={13} />}>
                  <StructureSection r={r} />
                </Sub>
                <Sub title="Evidence coverage" icon={<Globe size={13} />}>
                  <CoverageSection r={r} />
                </Sub>
              </Layer>
            </>
          ))}
        {tab === 'indicators' && (
          <div class="layer-body">
            {!r?.iocs?.length ? (
              <Empty title="No indicators" />
            ) : (
              <table class="t compact">
                <thead>
                  <tr>
                    <th style={{ width: '80px' }}>Type</th>
                    <th>Value</th>
                    <th style={{ width: '130px' }}>Role</th>
                    <th style={{ width: '110px' }}>Component</th>
                  </tr>
                </thead>
                <tbody>
                  {r.iocs.map((i) => (
                    <tr class="clickable" data-c={i.suspicious ? 'suspicious' : undefined} title={i.context ?? undefined} onClick={() => navigate(href(`/cases/${caseId}/indicators`, { q: i.value }))}>
                      <td class="muted">{i.type}</td>
                      <td class="mono">{i.value}</td>
                      <td class="small">{i.role}</td>
                      <td class="mono xs faint">{i.ref}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
            <div class="xs faint" style={{ marginTop: '8px' }}>
              Highlighted rows are indicators the engine considered risky in context; this is not an intelligence verdict. Click a row to see the indicator across the case.
            </div>
          </div>
        )}
        {tab === 'relations' && <Relations data={data} caseId={caseId} />}
        {tab === 'provenance' && <Provenance data={data} caseId={caseId} />}
      </div>
    </div>
  );
}

function LayerBars({ layers }: { layers: Record<string, number | null> }) {
  const keys = ['content', 'urls', 'attachments', 'infra', 'sender', 'semantic', 'delivery'];
  return (
    <div class="layers-mini">
      {keys.map((k) => (
        <div title={`${k}: ${layers[k] === null || layers[k] === undefined ? 'not comparable' : pct(layers[k])}`}>
          {k}
          <div class="bar">{layers[k] !== null && layers[k] !== undefined && <span data-c="accent" style={{ width: `${(layers[k] as number) * 100}%` }} />}</div>
        </div>
      ))}
    </div>
  );
}

function Relations({ data, caseId }: { data: MessageDetail; caseId: string }) {
  return (
    <div class="layer-body col" style={{ gap: 'var(--sp-4)' }}>
      <div>
        <div class="section-title">Local relationships ({data.related.length})</div>
        {data.related.length === 0 ? (
          <span class="small faint">No other message in this case passes the relationship threshold.</span>
        ) : (
          data.related.map((x) => (
            <div class="related-row">
              <div>
                <Badge c={x.tier === 'exact' ? 'malicious' : 'suspicious'} title={x.tier === 'exact' ? 'One highly specific artifact is shared (e.g. identical attachment, Reply-To mailbox, wallet)' : 'Several weaker indicators and/or high similarity combine above the threshold'}>
                  {x.tier}
                </Badge>
                <div class="mono xs faint" style={{ marginTop: '4px' }}>
                  {x.score.toFixed(2)}
                </div>
              </div>
              <div style={{ minWidth: 0 }}>
                <Link href={href(`/cases/${caseId}/messages`, { m: x.message.id })}>
                  <span class="break">{x.message.subject || '(no subject)'}</span>
                </Link>
                <div class="xs faint trunc">{x.message.from}</div>
                {x.hardLink && <div class="small">Hard link: {x.hardLink}</div>}
                <div class="shared-list">
                  {x.shared.map((s) => (
                    <Badge outline title={`${s.type}: ${s.value} · strength ${s.strength.toFixed(2)}${s.discounts.length ? ' · discounted: ' + s.discounts.join(', ') : ''}`}>
                      {s.family}: {short(s.value, 34)}
                    </Badge>
                  ))}
                </div>
                <LayerBars layers={x.layers} />
              </div>
              <div class="small muted right">
                indicators {x.indicatorScore.toFixed(2)}
                <br />
                similarity {x.similarity.toFixed(2)}
              </div>
            </div>
          ))
        )}
        <div class="xs faint" style={{ marginTop: '6px' }}>
          Relationship score = 1 − (1 − indicator evidence) × (1 − similarity). Shared infrastructure of large providers and popular domains is discounted.
        </div>
      </div>
      <div>
        <div class="section-title">External campaign records ({data.externalCampaigns.length})</div>
        {data.externalCampaigns.length === 0 ? (
          <span class="small faint">No intelligence event lists an indicator of this message.</span>
        ) : (
          data.externalCampaigns.map((x) => (
            <div class="related-row">
              <Badge c="intel">{x.source}</Badge>
              <div>
                <b class="break">{x.name}</b>
                <div class="small muted">
                  <span class="assess" data-a={x.assessment}>
                    {human(x.assessment)}
                  </span>{' '}
                  · {x.confidence} confidence{x.org ? ` · ${x.org}` : ''}
                  {x.date ? ` · ${new Date(x.date).toISOString().slice(0, 10)}` : ''}
                </div>
                <div class="shared-list">
                  {x.indicators.map((i) => (
                    <Badge outline title={`${human(i.matchType)} · strength ${i.strength.toFixed(2)}`}>
                      {i.type}: {short(i.value, 40)}
                    </Badge>
                  ))}
                </div>
              </div>
              <span />
            </div>
          ))
        )}
      </div>
    </div>
  );
}

function Provenance({ data, caseId }: { data: MessageDetail; caseId: string }) {
  const p = data.provenance;
  const pr = data.processing;
  return (
    <div class="layer-body col" style={{ gap: 'var(--sp-4)' }}>
      {p && (
        <div>
          <div class="section-title">Evidence lineage</div>
          <KV
            rows={[
              ['Evidence file', <Link href={href(`/cases/${caseId}/evidence`, { e: p.evidenceId })}>{p.evidenceName}</Link>],
              ['File SHA-256', <Mono value={p.evidenceSha256} />],
              ['Format', p.format ?? '—'],
              ['Derivation', `${p.derivation}${p.byteOffset !== null ? ` · byte offset ${fmtNum(p.byteOffset)}` : ''} · item ${p.containerIndex}`],
              ['Message SHA-256', <Mono value={p.messageSha256} />],
              ['Message size', `${fmtBytes(p.messageSize)} (${fmtNum(p.messageSize)} bytes)`],
              ['Stored as', p.storedAs === 'evidence' ? 'the original file itself' : 'derived artifact (extracted from the container; the container is preserved)'],
              ['Received', <><Time ms={p.receivedAt} /> by {p.uploadedBy ?? '—'}</>],
              ['Batch', <span class="mono">{p.batchId}</span>],
            ]}
          />
          {p.derivation.includes('msg') && <Notice c="warn">Outlook .msg items are reconstructed into RFC 5322 form from MAPI properties. The reconstruction is a derived artifact: header order, encodings and some headers can differ from what the mail server delivered.</Notice>}
        </div>
      )}
      {pr && (
        <div>
          <div class="section-title">Reproducibility</div>
          <KV
            rows={[
              ['Engine version', <span class="mono">{pr.engineVersion}</span>],
              ['Configuration hash', <Mono value={pr.configHash} />],
              ['Intelligence snapshot', <Mono value={pr.intelSnapshot} />],
              ['Result SHA-256', <Mono value={pr.reportSha256} />],
              ['Analysed', <Time ms={pr.analyzedAt} />],
              ['Duration', pr.durationMs !== null ? `${pr.durationMs} ms` : '—'],
              ['Attempts', String(pr.attempts)],
              ['Options', <span class="mono xs break">{JSON.stringify(pr.options)}</span>],
            ]}
          />
          <div class="xs faint" style={{ marginTop: '6px' }}>
            Re-running the same engine version with the same configuration and intelligence snapshot on the same bytes reproduces the result. Header-signature DKIM checks depend on DNS at analysis time and are recorded as such.
          </div>
        </div>
      )}
      <div>
        <div class="section-title">
          <History size={13} /> Processing history
        </div>
        <ul class="timeline">
          {data.history.map((h) => (
            <li>
              <span class="when">
                <Time ms={h.ts} />
              </span>
              <span>
                <b>{human(h.kind)}</b>
                {h.detail !== null && h.detail !== undefined && <div class="mono xs faint break">{JSON.stringify(h.detail)}</div>}
              </span>
            </li>
          ))}
        </ul>
      </div>
      {data.duplicates.length > 0 && (
        <div>
          <div class="section-title">Identical copies in this case ({data.duplicates.length})</div>
          {data.duplicates.map((x) => (
            <div>
              <Link href={href(`/cases/${caseId}/messages`, { m: x.id })} class="mono small">
                {x.id}
              </Link>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
