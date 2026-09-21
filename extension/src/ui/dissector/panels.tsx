// Dissector panels: one per evidence layer.
import { useMemo, useState } from 'preact/hooks';
import type { AttachmentAnalysis, AuthResult, Finding, LinkAnalysis, Report } from '../../../../engine/src/types';
import { toIocCsv, toMarkdown, toStixBundle } from '../../../../engine/src/export';
import { LAYER_LABELS } from '../../../../engine/src/campaign/similarity';
import { brandById } from '../../../../engine/src/data/brands';
import type { CampaignRecord, ReportSummary, StoredReport } from '../../shared/protocol';
import { defang, formatBytes, formatDateTime, formatDuration, initials, plural, relativeTime } from '../../shared/format';
import { Chip, CopyButton, Empty, SeverityIcon, VerdictIcon, download } from '../primitives';
import { FILE_FLAGS, INTENT_LABELS, LINK_FLAGS, flagLabel } from '../labels';
import {
  ArrowRight, AtSign, BadgeCheck, CircleCheck, CircleQuestionMark, Clock, Download, FileArchive, FileText, Fingerprint, GitFork, Globe, Hash, Lock, Mail,
  Network, Paperclip, Phone, QrCode, Reply, Search, Server, ShieldAlert, Shuffle, Target, TriangleAlert, User, X, Zap,
} from '../icons';

// ── Overview ────────────────────────────────────────────────────────────────

function FindingRow({ f }: { f: Finding }) {
  const [open, setOpen] = useState(false);
  const trust = f.weight < 0;
  const hasEvidence = !!f.evidence?.length;
  return (
    <div
      class="ms-finding"
      data-sev={f.severity}
      data-trust={trust ? '' : undefined}
      role={hasEvidence ? 'button' : undefined}
      tabIndex={hasEvidence ? 0 : undefined}
      aria-expanded={hasEvidence ? open : undefined}
      onClick={() => hasEvidence && setOpen(!open)}
      onKeyDown={(e) => {
        if (hasEvidence && (e.key === 'Enter' || e.key === ' ')) {
          e.preventDefault();
          setOpen(!open);
        }
      }}
    >
      <div class="ms-finding-icon">
        <SeverityIcon severity={f.severity} trust={trust} />
      </div>
      <div style={{ minWidth: 0 }}>
        <div class="ms-finding-title">{f.title}</div>
        <div class="ms-finding-detail">{f.detail}</div>
      </div>
      <div class="ms-finding-sev">{trust ? 'trust' : f.severity === 'info' ? 'note' : f.severity}</div>
      {open && hasEvidence && (
        <div class="ms-evidence" onClick={(e) => e.stopPropagation()}>
          <dl class="ms-kv">
            {f.evidence!.map((e) => (
              <>
                <dt>{e.label}</dt>
                <dd class={e.mono ? 'ms-mono' : undefined}>{e.value}</dd>
              </>
            ))}
          </dl>
        </div>
      )}
    </div>
  );
}

export function OverviewPanel({ r }: { r: Report }) {
  const risk = r.findings.filter((f) => f.weight > 0);
  const trust = r.findings.filter((f) => f.weight < 0);
  const notes = r.findings.filter((f) => f.weight === 0);
  const riskyLinks = r.links.filter((l) => l.risk >= 2).length;
  const files = r.attachments.filter((a) => !a.inline);
  const riskyFiles = r.attachments.filter((a) => a.risk >= 2).length;
  return (
    <div class="ms-dx-panel">
      <div class="ms-dx-strip">
        <div class="ms-dx-stat" data-tone={risk.length ? (r.verdict === 'safe' ? undefined : r.verdict) : 'safe'}>
          <b>{risk.length}</b>
          <span>warning signs</span>
        </div>
        <div class="ms-dx-stat" data-tone={riskyLinks ? 'danger' : undefined}>
          <b>
            {riskyLinks}
            <span class="ms-faint" style={{ fontSize: '12px' }}>/{r.links.length}</span>
          </b>
          <span>risky links</span>
        </div>
        <div class="ms-dx-stat" data-tone={riskyFiles ? 'danger' : undefined}>
          <b>
            {riskyFiles}
            <span class="ms-faint" style={{ fontSize: '12px' }}>/{files.length}</span>
          </b>
          <span>risky files</span>
        </div>
        <div class="ms-dx-stat">
          <b>{r.route.hops.length}</b>
          <span>server hops</span>
        </div>
      </div>

      <section class="ms-dx-section">
        <header>
          <span class="ms-eyebrow">Why MailShark thinks so</span>
        </header>
        {risk.length ? (
          <div class="ms-stagger">{risk.map((f) => <FindingRow key={f.id} f={f} />)}</div>
        ) : (
          <div class="ms-finding" data-sev="info" data-trust="">
            <div class="ms-finding-icon">
              <CircleCheck size={16} />
            </div>
            <div>
              <div class="ms-finding-title">No warning signs</div>
              <div class="ms-finding-detail">Nothing in the headers, links, attachments or wording matched a phishing technique.</div>
            </div>
            <div />
          </div>
        )}
      </section>
      {trust.length > 0 && (
        <section class="ms-dx-section">
          <header>
            <span class="ms-eyebrow">Trust signals</span>
          </header>
          {trust.map((f) => <FindingRow key={f.id} f={f} />)}
        </section>
      )}
      {notes.length > 0 && (
        <section class="ms-dx-section">
          <header>
            <span class="ms-eyebrow">Forensic notes</span>
          </header>
          {notes.map((f) => <FindingRow key={f.id} f={f} />)}
        </section>
      )}
    </div>
  );
}

// ── Sender ──────────────────────────────────────────────────────────────────

function authTone(r: AuthResult): 'safe' | 'danger' | 'caution' | undefined {
  if (r === 'pass' || r === 'bestguesspass') return 'safe';
  if (r === 'fail' || r === 'permerror') return 'danger';
  if (r === 'softfail' || r === 'temperror' || r === 'neutral') return 'caution';
  return undefined;
}

function AuthCell({ label, result, detail }: { label: string; result: AuthResult; detail?: string | null }) {
  const tone = authTone(result);
  return (
    <div class="ms-auth-cell" data-tone={tone}>
      <span class="ms-eyebrow">{label}</span>
      <b>
        {tone === 'safe' ? <CircleCheck /> : tone === 'danger' ? <X /> : tone === 'caution' ? <TriangleAlert /> : <CircleQuestionMark />}
        {result === 'unknown' ? 'n/a' : result}
      </b>
      {detail && <small>{detail}</small>}
    </div>
  );
}

function Tick({ ok }: { ok: boolean | null }) {
  if (ok === null) return <span class="ms-faint">—</span>;
  return ok ? <CircleCheck color="var(--ms-safe)" /> : <X color="var(--ms-danger)" />;
}

export function SenderPanel({ r }: { r: Report }) {
  const s = r.sender;
  const a = r.auth;
  const from = s.from;
  const fromOrg = from?.orgDomain ?? '';
  const tone = s.impersonatedBrand || s.lookalikeOf ? 'danger' : s.verifiedBrand ? 'safe' : undefined;
  const brandName = (id: string | null): string => (id ? (brandById(id)?.name ?? id) : '');
  return (
    <div class="ms-dx-panel">
      <div class="ms-idcard">
        <div class="ms-avatar" data-tone={tone}>
          {initials(from?.name ?? '', from?.address ?? '?')}
        </div>
        <div style={{ minWidth: 0 }}>
          <div class="ms-idcard-name">{from?.name || from?.address || 'Unknown sender'}</div>
          <div class="ms-idcard-addr">{from?.address ?? 'no From header'}</div>
          <div class="ms-row" style={{ flexWrap: 'wrap', gap: '5px', marginTop: '8px' }}>
            {s.verifiedBrand && <Chip tone="safe" icon={<BadgeCheck />}>Verified {brandName(s.verifiedBrand)}</Chip>}
            {s.impersonatedBrand && <Chip tone="danger" icon={<ShieldAlert />}>Pretends to be {brandName(s.impersonatedBrand)}</Chip>}
            {s.lookalikeOf && <Chip tone="danger" icon={<Target />}>Look-alike of {s.lookalikeOf}</Chip>}
            {s.displayNameAddress && <Chip tone="danger" icon={<AtSign />}>Fake address in name</Chip>}
            {s.isFreemail && <Chip icon={<Mail />}>Free webmail</Chip>}
            {s.firstTimeSender === true && <Chip tone="info" icon={<User />}>First-time sender</Chip>}
            {s.firstTimeSender === false && <Chip icon={<User />}>Known sender</Chip>}
          </div>
        </div>
      </div>

      <section class="ms-dx-section">
        <header>
          <span class="ms-eyebrow">Authentication</span>
          <span class="ms-faint" style={{ fontSize: '11.5px' }}>
            {a.source === 'trusted' ? `verified by ${a.authServId}` : a.source === 'topmost' ? `reported by ${a.authServId || 'receiver'}` : 'no results in message'}
          </span>
        </header>
        <div class="ms-auth">
          <AuthCell label="SPF" result={a.spf} detail={a.spfDomain} />
          <AuthCell label="DKIM" result={a.dkim} detail={a.dkimDomains.join(', ') || null} />
          <AuthCell label="DMARC" result={a.dmarc} detail={a.dmarcPolicy ? `policy ${a.dmarcPolicy}` : null} />
          <AuthCell label="ARC" result={a.arc} />
        </div>
      </section>

      <section class="ms-dx-section">
        <header>
          <span class="ms-eyebrow">Identity alignment with {fromOrg || 'From'}</span>
        </header>
        <div class="ms-card" style={{ padding: '2px 4px' }}>
          <table class="ms-align">
            <tbody>
              <tr>
                <td>From</td>
                <td class="ms-mono ms-break">{from?.address ?? '—'}</td>
                <td>
                  <Tick ok={from ? true : null} />
                </td>
              </tr>
              <tr>
                <td>Envelope</td>
                <td class="ms-mono ms-break">{s.returnPath?.address ?? a.spfDomain ?? '—'}</td>
                <td>
                  <Tick ok={a.spfAligned} />
                </td>
              </tr>
              <tr>
                <td>DKIM signer</td>
                <td class="ms-mono ms-break">{a.signatures.map((x) => `${x.domain} (s=${x.selector || '?'})`).join(', ') || '—'}</td>
                <td>
                  <Tick ok={a.dkimAligned} />
                </td>
              </tr>
              <tr>
                <td>Reply-To</td>
                <td class="ms-mono ms-break">{s.replyTo.map((x) => x.address).join(', ') || '—'}</td>
                <td>
                  <Tick ok={s.replyTo.length ? s.replyTo.every((x) => x.orgDomain === fromOrg) : null} />
                </td>
              </tr>
              {s.sender && (
                <tr>
                  <td>Sender</td>
                  <td class="ms-mono ms-break">{s.sender.address}</td>
                  <td>
                    <Tick ok={s.sender.orgDomain === fromOrg} />
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </section>

      {r.esp && (
        <section class="ms-dx-section">
          <header>
            <span class="ms-eyebrow">Bulk-mail infrastructure</span>
          </header>
          <div class="ms-card ms-card--pad">
            <dl class="ms-kv">
              <dt>Service</dt>
              <dd>{r.esp.name}</dd>
              <dt>Detected by</dt>
              <dd class="ms-mono">{r.esp.evidence}</dd>
              {r.esp.customerId && (
                <>
                  <dt>Customer ID</dt>
                  <dd class="ms-mono">{r.esp.customerId}</dd>
                </>
              )}
              {r.esp.campaignId && (
                <>
                  <dt>Campaign ID</dt>
                  <dd class="ms-mono">{r.esp.campaignId}</dd>
                </>
              )}
            </dl>
          </div>
        </section>
      )}
    </div>
  );
}

// ── Route ───────────────────────────────────────────────────────────────────

export function RoutePanel({ r }: { r: Report }) {
  const rt = r.route;
  if (!rt.hops.length)
    return (
      <Empty icon={<Network size={28} />} title="No delivery path recorded">
        This copy of the message has no Received headers (e.g. a draft or an exported copy without transport headers).
      </Empty>
    );
  return (
    <div class="ms-dx-panel">
      <div class="ms-card ms-card--pad">
        <dl class="ms-kv">
          <dt>Origin server</dt>
          <dd class="ms-mono">{rt.originHost ?? '—'}</dd>
          <dt>Origin IP</dt>
          <dd class="ms-row">
            <span class="ms-mono">{rt.originIp ?? '—'}</span>
            {rt.originIp && <CopyButton value={rt.originIp} label="Copy IP" />}
          </dd>
          <dt>Received by</dt>
          <dd class="ms-mono">{rt.receiverOrg ?? '—'}</dd>
          <dt>Transit time</dt>
          <dd>{formatDuration(rt.totalTransitSec)}</dd>
          <dt>Date header</dt>
          <dd>
            {formatDateTime(rt.dateHeader)}
            {rt.dateSkewSec !== null && Math.abs(rt.dateSkewSec) > 3600 && <span class="ms-faint"> · skew {formatDuration(rt.dateSkewSec)}</span>}
          </dd>
        </dl>
      </div>
      <section class="ms-dx-section">
        <header>
          <span class="ms-eyebrow">Delivery path: oldest → newest</span>
          <span class="ms-faint" style={{ fontSize: '11.5px' }}>dashed = claimed by sender</span>
        </header>
        <div class="ms-hops ms-stagger">
          {rt.hops.map((h) => {
            const isOrigin = !!rt.originIp && h.fromIp === rt.originIp && h.trusted;
            return (
              <div class="ms-hop" data-claimed={h.trusted ? undefined : ''} data-origin={isOrigin ? '' : undefined}>
                <div class="ms-hop-title">
                  <Server size={14} />
                  <span class="ms-truncate ms-mono">{h.fromRdns ?? h.fromHost ?? '(internal)'}</span>
                  <ArrowRight size={13} class="ms-faint" />
                  <span class="ms-truncate ms-mono">{h.byHost ?? '?'}</span>
                </div>
                <div class="ms-hop-sub">
                  {isOrigin && <Chip tone="accent" icon={<Target />}>Origin</Chip>}
                  {h.fromIp && <Chip mono>{h.fromIp}</Chip>}
                  {h.protocol && <Chip>{h.protocol}</Chip>}
                  {h.tls ? <Chip tone="safe" icon={<Lock />}>{h.tls}</Chip> : h.fromHost ? <Chip>no TLS noted</Chip> : null}
                  {h.delaySec !== null && <Chip icon={<Clock />}>+{formatDuration(h.delaySec)}</Chip>}
                  {!h.trusted && <Chip tone="caution">unverified</Chip>}
                </div>
              </div>
            );
          })}
        </div>
      </section>
    </div>
  );
}

// ── Links ───────────────────────────────────────────────────────────────────

function HighlightUrl({ l }: { l: LinkAnalysis }) {
  const host = l.host;
  const reg = l.regDomain;
  if (!host || !reg) return <>{l.url}</>;
  const i = l.url.indexOf(host);
  if (i < 0) return <>{l.url}</>;
  const j = i + host.length - reg.length;
  return (
    <>
      {l.url.slice(0, j)}
      <mark>{l.url.slice(j, i + host.length)}</mark>
      {l.url.slice(i + host.length)}
    </>
  );
}

export function LinksPanel({ r }: { r: Report }) {
  const [onlyRisky, setOnlyRisky] = useState(r.links.some((l) => l.risk >= 2));
  const links = useMemo(() => [...r.links].sort((a, b) => b.risk - a.risk), [r]);
  const shown = onlyRisky ? links.filter((l) => l.risk >= 1) : links;
  if (!r.links.length) return <Empty icon={<Globe size={28} />} title="No links in this email" />;
  return (
    <div class="ms-dx-panel">
      <div class="ms-row" style={{ justifyContent: 'space-between', marginBottom: '10px' }}>
        <span class="ms-faint" style={{ fontSize: '12px' }}>
          {plural(r.links.length, 'link')} · {new Set(r.links.map((l) => l.regDomain).filter(Boolean)).size} domains
        </span>
        <div class="ms-seg" role="group" aria-label="Filter links">
          <button type="button" aria-pressed={!onlyRisky} onClick={() => setOnlyRisky(false)}>
            All
          </button>
          <button type="button" aria-pressed={onlyRisky} onClick={() => setOnlyRisky(true)}>
            Flagged
          </button>
        </div>
      </div>
      {shown.length === 0 && <Empty title="No flagged links">All links point where they claim to.</Empty>}
      <div class="ms-stagger">
        {shown.slice(0, 120).map((l) => (
          <div class="ms-link" data-risk={l.risk}>
            {l.displayText && l.displayText !== l.url && (
              <div class="ms-link-text">
                <span class="ms-truncate">“{l.displayText}”</span>
              </div>
            )}
            <div class="ms-row" style={{ alignItems: 'flex-start' }}>
              <div class="ms-link-url ms-grow">
                <HighlightUrl l={l} />
              </div>
              <CopyButton value={defang(l.url)} label="Copy (defanged)" />
            </div>
            {(l.flags.length > 0 || l.lookalikeOf || l.intelHit || l.unwrappedFrom) && (
              <div class="ms-link-flags">
                {l.intelHit && <Chip tone="danger" icon={<ShieldAlert />}>{l.intelHit}</Chip>}
                {l.lookalikeOf && <Chip tone="danger" icon={<Target />}>imitates {l.lookalikeOf}</Chip>}
                {l.unwrappedFrom && <Chip tone="info">unwrapped from redirector</Chip>}
                {l.flags.map((fl) => {
                  const [label, tone] = flagLabel(LINK_FLAGS, fl);
                  return <Chip tone={tone}>{label}</Chip>;
                })}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

// ── Files ───────────────────────────────────────────────────────────────────

function FileCard({ a }: { a: AttachmentAnalysis }) {
  const [showEntries, setShowEntries] = useState(false);
  const icon = a.detectedType === 'zip' || a.detectedType === 'rar' || a.detectedType === '7z' ? <FileArchive size={18} /> : a.qr ? <QrCode size={18} /> : a.risk >= 2 ? <TriangleAlert size={18} /> : <FileText size={18} />;
  return (
    <div class="ms-file" data-risk={a.risk}>
      <div class="ms-file-head">
        <div class="ms-file-icon">{icon}</div>
        <div style={{ minWidth: 0 }}>
          <div class="ms-file-name">{a.filename}</div>
          <div class="ms-faint" style={{ fontSize: '12px' }}>
            {formatBytes(a.size)} · declared <span class="ms-mono">{a.declaredType}</span> · real <span class="ms-mono">{a.detectedType}</span>
            {a.inline ? ' · inline' : ''}
          </div>
        </div>
        <Chip tone={a.risk >= 3 ? 'danger' : a.risk === 2 ? 'caution' : undefined}>{a.risk >= 3 ? 'dangerous' : a.risk === 2 ? 'risky' : 'no issues'}</Chip>
      </div>
      {a.flags.length > 0 && (
        <div class="ms-link-flags">
          {a.flags.map((fl) => {
            const [label, tone] = flagLabel(FILE_FLAGS, fl);
            return <Chip tone={tone}>{label}</Chip>;
          })}
        </div>
      )}
      {a.qr && (
        <div class="ms-evidence" style={{ marginTop: '8px' }}>
          <dl class="ms-kv">
            <dt>QR decodes to</dt>
            <dd class="ms-mono">{a.qr}</dd>
          </dl>
        </div>
      )}
      {a.urls.length > 0 && (
        <div class="ms-faint" style={{ fontSize: '12px', marginTop: '8px' }}>
          Contains {plural(a.urls.length, 'link')} (listed under Links).
        </div>
      )}
      {a.entries.length > 0 && (
        <div style={{ marginTop: '8px' }}>
          <button type="button" class="ms-btn ms-btn--ghost ms-btn--sm" onClick={() => setShowEntries(!showEntries)}>
            <FileArchive /> {showEntries ? 'Hide' : 'Show'} {plural(a.entries.length, 'file')} inside
          </button>
          {showEntries && (
            <div class="ms-evidence" style={{ marginTop: '6px', maxHeight: '180px', overflow: 'auto' }}>
              {a.entries.map((e) => (
                <div class="ms-row ms-mono" style={{ fontSize: '11.5px', justifyContent: 'space-between' }}>
                  <span class="ms-truncate">{e.name}</span>
                  <span class="ms-faint">
                    {formatBytes(e.size)}
                    {e.encrypted ? ' · 🔒' : ''}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
      {(['sha256', 'sha1', 'md5'] as const).map((k) => (
        <div class="ms-hash">
          <span>{k.toUpperCase()}</span>
          <code>{a[k]}</code>
          <CopyButton value={a[k]} label={`Copy ${k}`} />
        </div>
      ))}
    </div>
  );
}

export function FilesPanel({ r }: { r: Report }) {
  const atts = [...r.attachments].sort((a, b) => b.risk - a.risk || Number(a.inline) - Number(b.inline));
  if (!atts.length) return <Empty icon={<Paperclip size={28} />} title="No attachments" />;
  return (
    <div class="ms-dx-panel ms-stagger">
      {atts.map((a) => (
        <FileCard key={a.sha256 + a.filename} a={a} />
      ))}
    </div>
  );
}

// ── Content ─────────────────────────────────────────────────────────────────

export function ContentPanel({ r }: { r: Report }) {
  const c = r.content;
  const h = r.html;
  const s = r.structure;
  const urgencyText = ['calm', 'mild', 'pushy', 'extreme'][c.urgency];
  return (
    <div class="ms-dx-panel">
      <section class="ms-dx-section">
        <header>
          <span class="ms-eyebrow">What it wants from you</span>
        </header>
        <div class="ms-card ms-card--pad">
          {c.intents.length ? (
            c.intents.slice(0, 4).map((i) => (
              <div class="ms-intent">
                <b style={{ fontSize: '13px', fontWeight: 600 }}>{INTENT_LABELS[i.id] ?? i.label}</b>
                <span class="ms-faint ms-mono" style={{ fontSize: '11.5px' }}>
                  {i.score.toFixed(1)}
                </span>
                <div class="ms-meter" data-tone={i.id === c.intent ? (r.verdict === 'safe' ? undefined : r.verdict) : undefined}>
                  <span style={{ width: `${Math.min(100, i.score * 9)}%` }} />
                </div>
                <div class="ms-row" style={{ gridColumn: '1 / 3', flexWrap: 'wrap', gap: '4px' }}>
                  {i.matches.slice(0, 6).map((m) => (
                    <Chip>“{m}”</Chip>
                  ))}
                </div>
              </div>
            ))
          ) : (
            <div class="ms-muted">No social-engineering playbook detected in the wording.</div>
          )}
        </div>
      </section>

      <section class="ms-dx-section">
        <header>
          <span class="ms-eyebrow">Pressure & tactics</span>
        </header>
        <div class="ms-card ms-card--pad">
          <dl class="ms-kv">
            <dt>Urgency</dt>
            <dd>
              <div class="ms-row">
                <div class="ms-meter ms-grow" data-tone={c.urgency >= 3 ? 'danger' : c.urgency === 2 ? 'caution' : 'safe'}>
                  <span style={{ width: `${(c.urgency / 3) * 100}%` }} />
                </div>
                <span style={{ fontSize: '12px', width: '56px' }}>{urgencyText}</span>
              </div>
            </dd>
            <dt>Asks you to</dt>
            <dd class="ms-row" style={{ flexWrap: 'wrap', gap: '4px' }}>
              {c.requestedActions.length ? c.requestedActions.map((x) => <Chip tone="caution" icon={<Zap />}>{x}</Chip>) : <span class="ms-faint">nothing specific</span>}
            </dd>
            <dt>Brands named</dt>
            <dd class="ms-row" style={{ flexWrap: 'wrap', gap: '4px' }}>
              {c.brandMentions.length ? c.brandMentions.map((b) => <Chip>{brandById(b)?.name ?? b}</Chip>) : <span class="ms-faint">none</span>}
            </dd>
            {c.phoneNumbers.length > 0 && (
              <>
                <dt>Phone numbers</dt>
                <dd class="ms-row" style={{ flexWrap: 'wrap', gap: '4px' }}>
                  {c.phoneNumbers.map((p) => (
                    <Chip mono icon={<Phone />}>
                      {p}
                    </Chip>
                  ))}
                </dd>
              </>
            )}
            <dt>Greeting</dt>
            <dd>{c.genericGreeting ? 'Generic (“Dear customer”)' : 'Personal or none'}</dd>
            <dt>Thread</dt>
            <dd>{c.fakeReply ? <Chip tone="danger" icon={<Reply />}>fake “Re:”</Chip> : 'consistent'}</dd>
            <dt>Language</dt>
            <dd>{c.language}</dd>
          </dl>
        </div>
      </section>

      <section class="ms-dx-section">
        <header>
          <span class="ms-eyebrow">Body & structure</span>
        </header>
        <div class="ms-card ms-card--pad">
          <dl class="ms-kv">
            <dt>Visible text</dt>
            <dd>{h.present ? `${h.visibleTextChars.toLocaleString()} chars` : 'plain text only'}</dd>
            {h.hiddenTextChars > 0 && (
              <>
                <dt>Hidden text</dt>
                <dd>{h.hiddenTextChars.toLocaleString()} chars</dd>
              </>
            )}
            <dt>Forms · scripts</dt>
            <dd>
              {h.forms.length} · {h.scripts}
            </dd>
            <dt>Images</dt>
            <dd>
              {h.images} ({h.trackingPixels} tracking pixel{h.trackingPixels === 1 ? '' : 's'})
            </dd>
            {h.remoteImageHosts.length > 0 && (
              <>
                <dt>Image hosts</dt>
                <dd class="ms-mono">{h.remoteImageHosts.slice(0, 6).join(', ')}</dd>
              </>
            )}
            <dt>MIME parts</dt>
            <dd>
              {s.partCount} parts, depth {s.maxDepth}
              {s.textHtmlDivergence !== null && ` · text/HTML divergence ${Math.round(s.textHtmlDivergence * 100)}%`}
            </dd>
            {(s.anomalies.length > 0 || s.duplicateHeaders.length > 0) && (
              <>
                <dt>Anomalies</dt>
                <dd class="ms-mono">{[...s.anomalies, ...s.duplicateHeaders.map((d) => `duplicate ${d}`)].join(', ')}</dd>
              </>
            )}
          </dl>
        </div>
      </section>

      {c.textPreview && (
        <section class="ms-dx-section">
          <header>
            <span class="ms-eyebrow">Text preview</span>
          </header>
          <blockquote class="ms-quote">{c.textPreview}</blockquote>
        </section>
      )}
    </div>
  );
}

// ── Campaign ────────────────────────────────────────────────────────────────

export function CampaignPanel({ campaign, members, currentId, onOpen }: { campaign: CampaignRecord | null; members: ReportSummary[]; currentId: string; onOpen?: (id: string) => void }) {
  if (!campaign)
    return (
      <Empty icon={<GitFork size={28} />} title="Not linked to a campaign (yet)">
        MailShark links emails that share templates, infrastructure or landing pages, even when senders and domains rotate. As more mail is dissected, related messages are grouped here.
      </Empty>
    );
  const p = campaign.profile;
  const maxAttrs = p.invariants.length + p.rotated.length || 1;
  return (
    <div class="ms-dx-panel">
      <div class="ms-camp-hero">
        <div class="ms-row" style={{ justifyContent: 'space-between' }}>
          <span class="ms-camp-id">{campaign.id}</span>
          <Chip tone={campaign.verdict} icon={<VerdictIcon verdict={campaign.verdict} size={12} />}>
            {campaign.verdict === 'danger' ? 'threat campaign' : campaign.verdict === 'caution' ? 'suspicious campaign' : 'bulk mailing'}
          </Chip>
        </div>
        <div class="ms-h3" style={{ marginTop: '6px' }}>
          {campaign.label}
        </div>
        <div class="ms-muted" style={{ fontSize: '12.5px', marginTop: '4px' }}>
          {plural(p.size, 'email')} · {plural(p.senders.length, 'sender domain')} · {plural(p.domains.length, 'link domain')}
          {p.attachments ? ` · ${plural(p.attachments, 'attachment variant')}` : ''} · first seen {relativeTime(p.firstSeen)}
        </div>
      </div>

      <section class="ms-dx-section">
        <header>
          <span class="ms-eyebrow">What the sender rotated</span>
          <Shuffle size={14} class="ms-faint" />
        </header>
        <div class="ms-inv">
          {p.rotated.length ? p.rotated.map((x) => <Chip tone="caution" icon={<Shuffle />}>{`${x.label} ×${x.values.length}`}</Chip>) : <span class="ms-faint">Nothing: identical copies.</span>}
        </div>
      </section>
      <section class="ms-dx-section">
        <header>
          <span class="ms-eyebrow">What stayed the same (campaign DNA)</span>
          <Fingerprint size={14} class="ms-faint" />
        </header>
        <div class="ms-inv">
          {p.invariants.length ? (
            p.invariants.map((x) => (
              <Chip tone="accent" icon={<Lock />} title={x.values[0]}>
                {x.label}
              </Chip>
            ))
          ) : (
            <span class="ms-faint">No single attribute is shared by every email: linked by overall similarity.</span>
          )}
        </div>
        <div class="ms-card ms-card--pad" style={{ marginTop: '10px' }}>
          <div class="ms-row" style={{ justifyContent: 'space-between' }}>
            <b style={{ fontSize: '13px' }}>Attacker cost to evade</b>
            <span class="ms-mono" style={{ fontSize: '12px' }}>
              {p.attackerCost} stable trait{p.attackerCost === 1 ? '' : 's'}
            </span>
          </div>
          <div class="ms-meter" style={{ marginTop: '8px' }}>
            <span style={{ width: `${Math.round((p.attackerCost / maxAttrs) * 100)}%` }} />
          </div>
          <div class="ms-faint" style={{ fontSize: '12px', marginTop: '6px' }}>
            To slip past campaign tracing they would have to change every trait above, not just the sender or the link.
          </div>
        </div>
      </section>

      <section class="ms-dx-section">
        <header>
          <span class="ms-eyebrow">Emails in this campaign</span>
        </header>
        <div class="ms-card ms-list">
          {members.map((m) => (
            <button type="button" class="ms-mailrow" onClick={() => onOpen?.(m.id)} disabled={!onOpen} style={{ cursor: onOpen ? 'pointer' : 'default' }}>
              <div class="ms-verdict-dot" data-v={m.verdict}>
                <VerdictIcon verdict={m.verdict} size={16} />
              </div>
              <div style={{ minWidth: 0 }}>
                <div class="ms-mailrow-title ms-truncate">
                  {m.subject || '(no subject)'}
                  {m.id === currentId && <span class="ms-faint"> · this email</span>}
                </div>
                <div class="ms-mailrow-sub ms-truncate">
                  {m.fromName ? `${m.fromName} · ` : ''}
                  {m.fromAddress}
                </div>
              </div>
              <span class="ms-faint" style={{ fontSize: '11.5px' }}>
                {relativeTime(m.date ?? m.storedAt)}
              </span>
            </button>
          ))}
        </div>
      </section>
      <div class="ms-faint" style={{ fontSize: '11.5px', marginTop: '12px' }}>
        Similarity layers: {Object.values(LAYER_LABELS).join(' · ')}.
      </div>
    </div>
  );
}

// ── Source & evidence ───────────────────────────────────────────────────────

export function SourcePanel({ stored }: { stored: StoredReport }) {
  const r = stored.report;
  const [q, setQ] = useState('');
  const base = `mailshark-${r.id.slice(0, 12)}`;
  const ql = q.trim().toLowerCase();
  const headers = ql ? r.headers.filter((h) => h.name.toLowerCase().includes(ql) || h.value.toLowerCase().includes(ql)) : r.headers;
  return (
    <div class="ms-dx-panel">
      <section class="ms-dx-section">
        <header>
          <span class="ms-eyebrow">Evidence integrity</span>
        </header>
        <div class="ms-card ms-card--pad">
          {(['sha256', 'sha1', 'md5'] as const).map((k) => (
            <div class="ms-hash">
              <span>{k.toUpperCase()}</span>
              <code>{r.hashes[k]}</code>
              <CopyButton value={r.hashes[k]} label={`Copy ${k}`} />
            </div>
          ))}
          <div class="ms-faint" style={{ fontSize: '11.5px', marginTop: '8px' }}>
            {formatBytes(r.sizeBytes)} · analysed {formatDateTime(r.analyzedAt)} · engine {r.engineVersion} · {Math.round(r.timings['total'] ?? 0)} ms
          </div>
        </div>
      </section>

      <section class="ms-dx-section">
        <header>
          <span class="ms-eyebrow">Export</span>
        </header>
        <div class="ms-export">
          <button type="button" class="ms-btn" onClick={() => download(`${base}.md`, toMarkdown(r), 'text/markdown')}>
            <FileText /> Case report (.md)
          </button>
          <button type="button" class="ms-btn" onClick={() => download(`${base}.stix.json`, JSON.stringify(toStixBundle(r), null, 2))}>
            <Hash /> STIX 2.1 bundle
          </button>
          <button type="button" class="ms-btn" onClick={() => download(`${base}-iocs.csv`, toIocCsv(r), 'text/csv')}>
            <Download /> IOCs (.csv)
          </button>
          <button type="button" class="ms-btn" onClick={() => download(`${base}.json`, JSON.stringify(stored, null, 2))}>
            <Download /> Full analysis (.json)
          </button>
        </div>
      </section>

      <section class="ms-dx-section">
        <header>
          <span class="ms-eyebrow">Headers ({r.headers.length})</span>
        </header>
        <div class="ms-input-wrap" style={{ marginBottom: '8px' }}>
          <Search />
          <input class="ms-input" type="search" placeholder="Filter headers…" value={q} onInput={(e) => setQ((e.target as HTMLInputElement).value)} />
        </div>
        <div class="ms-headers">
          {headers.map((h) => (
            <div class="ms-header-row" data-hit={ql ? '' : undefined}>
              <b>{h.name}</b>
              <span>{h.value}</span>
            </div>
          ))}
          {!headers.length && <div class="ms-header-row"><span class="ms-faint">No header matches “{q}”.</span></div>}
        </div>
      </section>
    </div>
  );
}
