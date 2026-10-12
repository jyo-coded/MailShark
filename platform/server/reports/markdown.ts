// Markdown rendering of a ForensicReport. All evidence-derived text is escaped (no Markdown or HTML
// injection) and network indicators are defanged so the document never contains live links.
import { defang } from '../../../engine/src/iocs';
import type { ForensicReport, ReportMessage } from './model';

const NET = new Set(['url', 'domain', 'hostname', 'ipv4', 'ipv6', 'email']);

/** Neutralise live links inside free text: URLs, www hosts and e-mail addresses (idempotent). */
export function defangInline(s: string): string {
  return s
    .replace(/\b(?:https?|ftp):\/\/[^\s<>"'`|)\]]+/gi, (u) => defang(u))
    .replace(/\bwww\.[a-z0-9-]+(?:\.[a-z0-9-]+)+[^\s<>"'`|)\]]*/gi, (u) => defang(u))
    .replace(/\b[\w.+-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)+\b/gi, (e) => defang(e));
}

/** Escape text for Markdown prose / table cells. */
export function md(s: string | null | undefined, max = 400): string {
  if (s === null || s === undefined || s === '') return '—';
  const one = defangInline(s.replace(/[\r\n\t]+/g, ' ')).slice(0, max);
  return one.replace(/[\\`*_{}[\]()<>#+!|~]/g, (c) => '\\' + c);
}

/** Inline code span that cannot be broken out of. */
export function code(s: string | null | undefined, max = 300): string {
  if (!s) return '—';
  const one = defangInline(s.replace(/[\r\n\t]+/g, ' ')).slice(0, max);
  const ticks = (one.match(/`+/g) ?? []).reduce((m, t) => Math.max(m, t.length), 0);
  const fence = '`'.repeat(ticks + 1);
  return `${fence}${ticks ? ' ' : ''}${one}${ticks ? ' ' : ''}${fence}`.replace(/\|/g, '\\|');
}

const indicatorText = (type: string, value: string): string => (NET.has(type) ? defang(value) : value);

function table(headers: string[], rows: string[][]): string[] {
  return [`| ${headers.join(' | ')} |`, `| ${headers.map(() => '---').join(' | ')} |`, ...rows.map((r) => `| ${r.join(' | ')} |`)];
}

const CLASS_ORDER = ['malicious', 'suspicious', 'inconclusive', 'failed', 'benign', 'duplicate', 'queued', 'running'];

function messageBlock(m: ReportMessage, out: string[]): void {
  const c = m.classification;
  out.push(`### ${md(m.summary.subject || '(no subject)', 200)}`);
  out.push('');
  out.push(...table(['Field', 'Value'], [
    ['Message ID (platform)', code(m.id)],
    ['Classification', c ? `**${md(c.class)}** · severity ${md(c.severity)} · confidence ${md(c.confidence)}` : md(m.status)],
    ['Risk score / evidence coverage', c ? `${c.riskScore ?? '—'} / ${c.evidenceCoverage !== null ? Math.round((c.evidenceCoverage ?? 0) * 100) + '%' : '—'}` : '—'],
    ['From', code(m.summary.from ? indicatorText('email', m.summary.from) : null)],
    ['Date (header)', md(m.summary.date)],
    ['Message-ID header', code(m.summary.messageId)],
    ['Evidence', `${code(m.evidenceId)} · ${md(m.derivation)} · item ${m.containerIndex}${m.byteOffset !== null ? ` @ byte ${m.byteOffset}` : ''}`],
    ['Message SHA-256', code(m.sha256)],
  ]));
  out.push('');
  if (c?.rationale.length) {
    out.push('**Why this classification** (analytical inference):');
    for (const r of c.rationale) out.push(`- ${md(r)}`);
    out.push('');
  }
  if (m.observations) {
    const a = m.observations.authentication;
    const r = m.observations.route;
    out.push('**Observed facts**');
    if (a) out.push(`- Authentication (${md(a.source === 'trusted' ? `written by receiving server ${a.reportedBy ?? ''}` : a.source === 'topmost' ? 'unverified origin' : 'not present in evidence')}): SPF ${md(a.spf)}, DKIM ${md(a.dkim)}, DMARC ${md(a.dmarc)}${a.dmarcPolicy ? ` (p=${md(a.dmarcPolicy)})` : ''}, ARC ${md(a.arc)}`);
    if (r) out.push(`- Origin: ${r.originIp ? code(defang(r.originIp)) : 'not determined'}${r.originHost ? ` (${code(defang(r.originHost))})` : ''}${r.originAsn ? `, AS${r.originAsn.asn} ${md(r.originAsn.name)}` : ''}; ${r.hops.length} Received hop(s), receiver ${md(r.receiver)}`);
    for (const d of m.observations.dkim) out.push(`- DKIM d=${code(d.domain)} s=${code(d.selector)} (${md(d.algorithm)}): body hash ${md(d.bodyHash)}, signature ${md(d.signature)}`);
    const missing = m.observations.coverage.filter((l) => l.status !== 'available' && l.status !== 'not-applicable');
    for (const l of missing) out.push(`- Evidence layer "${md(l.layer)}": ${md(l.status)}: ${md(l.note)}`);
    out.push('');
  }
  const positives = m.findings.filter((f) => f.weight > 0 || f.category === 'integrity');
  if (positives.length) {
    out.push('**Findings**');
    out.push('');
    for (const f of positives) {
      out.push(`- **[${f.severity.toUpperCase()}] ${md(f.title, 200)}** (${md(f.method ?? 'heuristic')}, weight ${f.weight}): ${md(f.detail, 600)}`);
      for (const e of f.evidence.slice(0, 6)) out.push(`  - ${md(e.label)}: ${code(e.value, 200)}`);
      if (f.components.length) out.push(`  - Located in: ${f.components.map((x) => code(x)).join(', ')}`);
      if (f.attack.length) out.push(`  - ATT&CK: ${f.attack.map((t) => `${t.id} ${md(t.name)}`).join('; ')}`);
      if (f.limitations) out.push(`  - Limitation: ${md(f.limitations)}`);
      if (f.recommendedActions.length) out.push(`  - Next steps: ${f.recommendedActions.map((x) => md(x)).join(' ')}`);
    }
    out.push('');
  }
  const intel = m.intelligence.filter((i) => i.strength > 0);
  if (intel.length) {
    out.push('**External intelligence** (third-party listings, not observations):');
    out.push('');
    out.push(...table(['Source', 'Indicator', 'Match', 'Threat / family', 'Listed', 'Reference'], intel.slice(0, 30).map((i) => [md(i.source), code(indicatorText(i.indicatorType, i.indicator), 120), md(i.matchType), md([i.threat, i.family].filter(Boolean).join(' / ')), md(i.firstSeen?.slice(0, 10)), code(i.reference ? defang(i.reference) : null, 120)])));
    out.push('');
  }
  const iocs = m.indicators.filter((i) => i.suspicious || ['from', 'reply-to', 'origin-ip', 'client-ip', 'attachment', 'link'].includes(i.role)).slice(0, 40);
  if (iocs.length) {
    out.push('**Indicators** (defanged):');
    out.push('');
    out.push(...table(['Type', 'Value', 'Role', 'Component'], iocs.map((i) => [md(i.type), code(indicatorText(i.type, i.value), 160), md(i.role), code(i.component)])));
    out.push('');
  }
  if (m.campaign) out.push(`**Campaign cluster:** ${code(m.campaign.clusterId)} (${md(m.campaign.label)})`, '');
  if (m.error) out.push(`**Analysis error:** ${code(m.error.code)}: ${md(m.error.detail)}`, '');
  out.push(`<sub>Processed ${md(m.processing.analyzedAt)} · engine ${md(m.processing.engineVersion)} · config ${code(m.processing.configHash)} · intel snapshot ${code(m.processing.intelSnapshot)} · result SHA-256 ${code(m.processing.resultSha256)}</sub>`);
  out.push('');
}

export function renderMarkdown(r: ForensicReport): string {
  const out: string[] = [];
  out.push(`# Forensic report: ${md(r.case.name, 200)}`);
  out.push('');
  out.push(...table(['', ''], [
    ['Report ID', code(r.report.id)],
    ['Generated', `${md(r.report.generatedAt)} by ${md(r.report.generatedBy.displayName)} (${md(r.report.generatedBy.username)})`],
    ['Scope', md(r.report.scope.description)],
    ['Case reference', md(r.case.reference)],
    ['Platform / engine', `${md(r.report.platform.version)} / ${r.provenance.engineVersions.map((v) => md(v)).join(', ') || '—'}`],
    ['Report data SHA-256', code(r.integrity.dataSha256)],
  ]));
  out.push('');
  out.push('> Observed facts (header values, hashes, indicators) are reported separately from analytical findings and from third-party intelligence. Network indicators are defanged. The report data hash identifies the JSON rendering of the same report.');
  out.push('');

  const s = r.statistics;
  out.push('## 1. Summary');
  out.push('');
  out.push(...table(['Measure', 'Count'], [
    ['Evidence files (rejected / duplicate)', `${s.evidenceFiles} (${s.rejectedFiles} / ${s.duplicateFiles})`],
    ['Messages analysed / failed / pending', `${s.analyzed} / ${s.failed} / ${s.pending}`],
    ...CLASS_ORDER.filter((k) => s.byClass[k]).map((k) => [`Classified ${k}`, String(s.byClass[k])]),
    ['Messages with intelligence matches', String(s.withIntelMatches)],
    ['Campaign clusters (threat)', `${s.clusters} (${s.threatClusters})`],
    ['Reported external campaign associations', String(s.externalAssociations)],
  ]));
  out.push('');

  out.push('## 2. Evidence received');
  out.push('');
  out.push(...table(['File', 'Format', 'Size', 'SHA-256', 'Received', 'By', 'Status'], r.evidence.map((e) => [md(e.originalName, 80), md(e.format), String(e.size), code(e.sha256), md(e.receivedAt), md(e.uploadedBy), md(e.status + (e.error ? `: ${e.error.code}` : ''))])));
  out.push('');

  out.push('## 3. Messages');
  out.push('');
  const detailed = r.messages.filter((m) => ['malicious', 'suspicious', 'inconclusive'].includes(m.classification?.class ?? ''));
  for (const cls of ['malicious', 'suspicious', 'inconclusive']) {
    const list = detailed.filter((m) => m.classification?.class === cls);
    if (!list.length) continue;
    out.push(`## 3.${cls === 'malicious' ? 1 : cls === 'suspicious' ? 2 : 3} ${cls[0]?.toUpperCase()}${cls.slice(1)} (${list.length})`);
    out.push('');
    for (const m of list) messageBlock(m, out);
  }
  const benign = r.messages.filter((m) => m.classification?.class === 'benign');
  if (benign.length) {
    out.push(`## 3.4 Benign (${benign.length})`);
    out.push('');
    out.push(...table(['Subject', 'From', 'Risk', 'Coverage', 'Confidence', 'SHA-256'], benign.map((m) => [md(m.summary.subject, 80), code(m.summary.from ? defang(m.summary.from) : null, 60), String(m.classification?.riskScore ?? '—'), m.classification?.evidenceCoverage !== null && m.classification?.evidenceCoverage !== undefined ? `${Math.round(m.classification.evidenceCoverage * 100)}%` : '—', md(m.classification?.confidence), code(m.sha256.slice(0, 16) + '…')])));
    out.push('');
  }
  const failed = r.messages.filter((m) => m.status === 'failed' || m.status === 'duplicate' || m.status === 'queued' || m.status === 'running');
  if (failed.length) {
    out.push(`## 3.5 Not analysed (${failed.length})`);
    out.push('');
    out.push(...table(['Message', 'Status', 'Detail'], failed.map((m) => [code(m.id), md(m.status), m.duplicateOf ? `duplicate of ${code(m.duplicateOf)}` : md(m.error ? `${m.error.code}: ${m.error.detail ?? ''}` : null)])));
    out.push('');
  }

  out.push('## 4. Campaign correlation (analytical inference)');
  out.push('');
  if (!r.campaigns.clusters.length) out.push('No clusters of related messages were found in this scope.', '');
  for (const c of r.campaigns.clusters) {
    out.push(`### ${code(c.id)} ${md(c.label)}`);
    out.push('');
    out.push(`${c.size} messages · verdict ${md(c.verdict)} · confidence ${md(c.confidence)} · cohesion ${c.cohesion} · ${c.exactRelationships} exact relationship(s) · ${md(c.firstSeen?.slice(0, 10))} → ${md(c.lastSeen?.slice(0, 10))}`);
    out.push('');
    if (c.invariants.length) out.push(`- Stayed constant: ${c.invariants.map((i) => md(i.attribute)).join(', ')}`);
    if (c.rotated.length) out.push(`- Rotated: ${c.rotated.map((i) => md(i.attribute)).join(', ')}`);
    for (const si of c.sharedIndicators.slice(0, 10)) out.push(`- Shared ${md(si.family)}: ${code(indicatorText(si.type, si.value), 120)} in ${si.messages} messages (strength ${si.strength}${si.discounts.length ? `; discounted: ${si.discounts.map((d) => md(d)).join('; ')}` : ''})`);
    for (const x of c.externalAssociations) out.push(`- External: ${md(x.source)} "${md(x.name)}" (${md(x.assessment)}, ${md(x.confidence)})`);
    out.push('');
  }

  out.push('## 5. External campaign associations (third-party records)');
  out.push('');
  if (!r.campaigns.external.length) out.push('No message in this scope shares indicators with an externally documented campaign or event in the configured sources. This is not evidence that the messages are benign.', '');
  for (const x of r.campaigns.external) {
    out.push(`### ${md(x.name, 200)}`);
    out.push('');
    out.push(`Source ${md(x.source)} · event ${code(x.eventId)} · ${md(x.organisation)} · ${md(x.date?.slice(0, 10))} · **${md(x.assessment)}** (${md(x.confidence)})${x.reference ? ` · reference ${code(defang(x.reference), 160)}` : ''}`);
    out.push('');
    for (const r2 of x.rationale) out.push(`- ${md(r2)}`);
    for (const i of x.matchedIndicators.slice(0, 15)) out.push(`- ${md(i.type)} ${code(indicatorText(i.type, i.value), 120)}: ${md(i.matchType)}, strength ${i.strength}${i.strength === 0 ? ' (not counted)' : ''}`);
    out.push('');
  }

  out.push('## 6. Intelligence sources consulted');
  out.push('');
  out.push(...table(['Source', 'Provider', 'Type', 'Status', 'Last update', 'Records'], r.provenance.intelligenceSources.map((x) => [md(x.name), md(x.provider), md(`${x.kind} / ${x.attribution}`), md(x.status), md(x.lastSuccess), String(x.records + x.events)])));
  out.push('');
  if (r.provenance.onlineLookups.length) {
    out.push('Online lookups performed for this case (indicator disclosed to the listed services):');
    for (const l of r.provenance.onlineLookups) out.push(`- ${md(l.at)} by ${md(l.by)}: ${code(l.indicator)}`);
    out.push('');
  }

  out.push('## 7. Provenance');
  out.push('');
  out.push(`- Engine versions: ${r.provenance.engineVersions.map((v) => code(v)).join(', ') || '—'}`);
  out.push(`- Configuration hashes: ${r.provenance.configHashes.map((v) => code(v)).join(', ') || '—'}`);
  out.push(`- Intelligence snapshots: ${r.provenance.intelSnapshots.map((v) => code(v)).join(', ') || '—'}`);
  out.push(`- Correlation: ${md(r.provenance.correlation.method)} (run ${md(r.provenance.correlation.correlatedAt)}, version ${r.provenance.correlation.version})`);
  out.push('');

  out.push('## 8. Limitations');
  out.push('');
  for (const l of r.limitations) out.push(`- ${md(l, 1000)}`);
  out.push('');
  out.push(`<sub>Report ${code(r.report.id)} · data SHA-256 ${code(r.integrity.dataSha256)} · ${md(r.integrity.note, 600)}</sub>`);
  out.push('');
  return out.join('\n');
}
