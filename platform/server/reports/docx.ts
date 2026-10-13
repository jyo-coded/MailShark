// DOCX rendering of a ForensicReport (same data as the JSON and Markdown renderings). Text from
// evidence is inserted as plain runs (the library XML-escapes it); characters that are invalid in
// XML 1.0 are removed so a hostile subject line cannot corrupt the document.
import { AlignmentType, BorderStyle, Document, Footer, Header, HeadingLevel, Packer, PageNumber, Paragraph, ShadingType, Table, TableCell, TableRow, TextRun, WidthType, PageBreak } from 'docx';
import { defang } from '../../../engine/src/iocs';
import type { ForensicReport, ReportMessage } from './model';
import { defangInline } from './markdown';

const FONT = 'Calibri';
const MONO = 'Consolas';
const INK = '1D2433';
const MUTED = '5B6577';
const RULE = 'C9CFD8';
const HEAD_FILL = 'EEF1F5';
const CLASS_COLOR: Record<string, string> = { malicious: 'B42318', suspicious: 'B54708', inconclusive: '475467', benign: '027A48', failed: '6C2BD9', duplicate: '667085' };
const NET = new Set(['url', 'domain', 'hostname', 'ipv4', 'ipv6', 'email']);

// eslint-disable-next-line no-control-regex
const clean = (s: string | null | undefined, max = 2000): string => defangInline(s ?? '').replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f￾￿]/g, '').slice(0, max);
const ind = (type: string, v: string): string => (NET.has(type) ? defang(v) : v);

function run(text: string, o: { bold?: boolean; mono?: boolean; color?: string; size?: number; italics?: boolean } = {}): TextRun {
  // A leading newline becomes a real line break (plain "\n" is not rendered inside a Word run).
  const brk = text.startsWith('\n');
  const body = clean(text.replace(/^\n/, '').replace(/\n+$/, ''));
  return new TextRun({ text: body, ...(brk ? { break: 1 } : {}), bold: o.bold ?? false, italics: o.italics ?? false, font: o.mono ? MONO : FONT, size: o.size ?? (o.mono ? 17 : 20), color: o.color ?? INK });
}

function para(children: TextRun[] | string, o: { spacingAfter?: number; heading?: (typeof HeadingLevel)[keyof typeof HeadingLevel]; align?: (typeof AlignmentType)[keyof typeof AlignmentType]; bullet?: boolean } = {}): Paragraph {
  return new Paragraph({
    children: typeof children === 'string' ? [run(children)] : children,
    spacing: { after: o.spacingAfter ?? 100 },
    ...(o.heading ? { heading: o.heading } : {}),
    ...(o.align ? { alignment: o.align } : {}),
    ...(o.bullet ? { bullet: { level: 0 } } : {}),
  });
}

function cell(content: string | TextRun[], o: { header?: boolean; width?: number; mono?: boolean; color?: string } = {}): TableCell {
  return new TableCell({
    children: [new Paragraph({ children: typeof content === 'string' ? [run(content || '—', { bold: o.header ?? false, mono: o.mono ?? false, size: o.mono ? 16 : 18, ...(o.color ? { color: o.color } : {}) })] : content, spacing: { after: 40 } })],
    margins: { top: 60, bottom: 60, left: 90, right: 90 },
    ...(o.header ? { shading: { fill: HEAD_FILL, type: ShadingType.CLEAR, color: 'auto' } } : {}),
    ...(o.width ? { width: { size: o.width, type: WidthType.PERCENTAGE } } : {}),
  });
}

function table(headers: string[], rows: (string | TextRun[])[][], widths?: number[], monoCols: number[] = []): Table {
  const border = { style: BorderStyle.SINGLE, size: 4, color: RULE };
  return new Table({
    width: { size: 100, type: WidthType.PERCENTAGE },
    borders: { top: border, bottom: border, left: border, right: border, insideHorizontal: border, insideVertical: border },
    rows: [
      new TableRow({ tableHeader: true, children: headers.map((h, i) => cell(h, { header: true, ...(widths?.[i] ? { width: widths[i] } : {}) })) }),
      ...rows.map((r) => new TableRow({ children: r.map((v, i) => cell(v, { mono: monoCols.includes(i), ...(widths?.[i] ? { width: widths[i] } : {}) })) })),
    ],
  });
}

function kv(rows: [string, string, boolean?][]): Table {
  return table(['Field', 'Value'], rows.map(([k, v, mono]) => [k, mono ? [run(v || '—', { mono: true, size: 16 })] : v || '—']), [28, 72]);
}

const h = (text: string, level: (typeof HeadingLevel)[keyof typeof HeadingLevel]): Paragraph => new Paragraph({ heading: level, children: [new TextRun({ text: clean(text, 300), font: FONT, color: INK, bold: true })], spacing: { before: 240, after: 120 } });

function messageSection(m: ReportMessage): (Paragraph | Table)[] {
  const out: (Paragraph | Table)[] = [];
  const c = m.classification;
  const color = CLASS_COLOR[c?.class ?? m.status] ?? INK;
  out.push(new Paragraph({ children: [run(clean(m.summary.subject || '(no subject)', 300), { bold: true, size: 22 })], spacing: { before: 200, after: 60 } }));
  out.push(para([run((c?.class ?? m.status).toUpperCase(), { bold: true, color, size: 18 }), run(c ? `   severity ${c.severity ?? '—'} · confidence ${c.confidence ?? '—'} · risk ${c.riskScore ?? '—'} · evidence coverage ${c.evidenceCoverage !== null && c.evidenceCoverage !== undefined ? Math.round(c.evidenceCoverage * 100) + '%' : '—'}` : '', { color: MUTED, size: 18 })]));
  out.push(kv([
    ['Platform message ID', m.id, true],
    ['From', m.summary.from ? defang(m.summary.from) : '—', true],
    ['Date (header)', m.summary.date ?? '—'],
    ['Message-ID header', m.summary.messageId ?? '—', true],
    ['Evidence item', `${m.evidenceId} · ${m.derivation} · item ${m.containerIndex}${m.byteOffset !== null ? ` @ byte ${m.byteOffset}` : ''}`, true],
    ['Message SHA-256', m.sha256, true],
  ]));
  if (c?.rationale.length) {
    out.push(para([run('Why this classification (analytical inference)', { bold: true })], { spacingAfter: 40 }));
    for (const r of c.rationale) out.push(para(r, { bullet: true, spacingAfter: 40 }));
  }
  if (m.observations) {
    out.push(para([run('Observed facts', { bold: true })], { spacingAfter: 40 }));
    const a = m.observations.authentication;
    if (a) out.push(para(`Authentication (${a.source === 'trusted' ? `written by receiving server ${a.reportedBy ?? ''}` : a.source === 'topmost' ? 'origin unverified' : 'not present in this evidence'}): SPF ${a.spf}, DKIM ${a.dkim}, DMARC ${a.dmarc}${a.dmarcPolicy ? ` (p=${a.dmarcPolicy})` : ''}, ARC ${a.arc}.`, { bullet: true, spacingAfter: 40 }));
    const r = m.observations.route;
    if (r) out.push(para(`Origin ${r.originIp ? defang(r.originIp) : 'not determined'}${r.originHost ? ` (${defang(r.originHost)})` : ''}${r.originAsn ? `, AS${r.originAsn.asn} ${r.originAsn.name ?? ''}` : ''}; ${r.hops.length} Received hops; receiver ${r.receiver ?? '—'}.`, { bullet: true, spacingAfter: 40 }));
    for (const d of m.observations.dkim) out.push(para(`DKIM d=${d.domain} s=${d.selector} (${d.algorithm}): body hash ${d.bodyHash}, signature ${d.signature}.`, { bullet: true, spacingAfter: 40 }));
    for (const l of m.observations.coverage.filter((x) => x.status !== 'available' && x.status !== 'not-applicable')) out.push(para(`${l.layer}: ${l.status}. ${l.note}`, { bullet: true, spacingAfter: 40 }));
  }
  const findings = m.findings.filter((f) => f.weight > 0 || f.category === 'integrity');
  if (findings.length) {
    out.push(para([run('Findings', { bold: true })], { spacingAfter: 40 }));
    out.push(
      table(
        ['Severity', 'Finding', 'Evidence and basis'],
        findings.map((f) => [
          [run(f.severity.toUpperCase(), { bold: true, size: 16, color: f.severity === 'critical' || f.severity === 'high' ? CLASS_COLOR['malicious'] as string : f.severity === 'medium' ? CLASS_COLOR['suspicious'] as string : MUTED })],
          [run(f.title, { bold: true, size: 18 }), run(`\n${f.detail}`, { size: 17 })],
          [
            ...f.evidence.slice(0, 4).map((e, i) => run(`${i ? '\n' : ''}${e.label}: ${e.value}`.slice(0, 220), { mono: true, size: 15 })),
            run(`${f.evidence.length ? '\n' : ''}Method: ${f.method ?? 'heuristic'} · weight ${f.weight}${f.components.length ? ` · ${f.components.join(', ')}` : ''}`, { size: 15, color: MUTED }),
            ...(f.attack.length ? [run(`\nATT&CK: ${f.attack.map((t) => t.id).join(', ')}`, { size: 15, color: MUTED })] : []),
            ...(f.limitations ? [run(`\nLimitation: ${f.limitations}`, { size: 15, color: MUTED, italics: true })] : []),
          ],
        ]),
        [12, 38, 50],
      ),
    );
  }
  const intel = m.intelligence.filter((i) => i.strength > 0);
  if (intel.length) {
    out.push(para([run('External intelligence (third-party listings)', { bold: true })], { spacingAfter: 40 }));
    out.push(table(['Source', 'Indicator', 'Match', 'Threat / family', 'Listed'], intel.slice(0, 25).map((i) => [i.source, ind(i.indicatorType, i.indicator).slice(0, 160), i.matchType, [i.threat, i.family].filter(Boolean).join(' / ') || '—', i.firstSeen?.slice(0, 10) ?? '—']), [16, 40, 14, 20, 10], [1]));
  }
  const iocs = m.indicators.filter((i) => i.suspicious || ['from', 'reply-to', 'origin-ip', 'client-ip', 'attachment'].includes(i.role)).slice(0, 30);
  if (iocs.length) {
    out.push(para([run('Indicators (defanged)', { bold: true })], { spacingAfter: 40 }));
    out.push(table(['Type', 'Value', 'Role', 'Component'], iocs.map((i) => [i.type, ind(i.type, i.value).slice(0, 180), i.role, i.component]), [12, 56, 16, 16], [1, 3]));
  }
  if (m.error) out.push(para([run('Analysis error: ', { bold: true }), run(`${m.error.code}: ${m.error.detail ?? ''}`)]));
  out.push(para([run(`Processed ${m.processing.analyzedAt ?? '—'} · engine ${m.processing.engineVersion ?? '—'} · config ${m.processing.configHash ?? '—'} · intel snapshot ${m.processing.intelSnapshot ?? '—'} · result SHA-256 ${m.processing.resultSha256 ?? '—'}`, { size: 14, color: MUTED })]));
  return out;
}

export async function renderDocx(r: ForensicReport): Promise<Buffer> {
  const s = r.statistics;
  const body: (Paragraph | Table)[] = [];
  // Cover
  body.push(new Paragraph({ children: [run('FORENSIC EMAIL ANALYSIS REPORT', { bold: true, size: 20, color: MUTED })], spacing: { before: 1200, after: 200 } }));
  body.push(new Paragraph({ children: [run(r.case.name, { bold: true, size: 44 })], spacing: { after: 200 } }));
  body.push(kv([
    ['Case reference', r.case.reference ?? '—'],
    ['Report ID', r.report.id, true],
    ['Scope', r.report.scope.description],
    ['Generated', `${r.report.generatedAt} by ${r.report.generatedBy.displayName} (${r.report.generatedBy.username})`],
    ['Platform / engine', `MailShark ${r.report.platform.version} / engine ${r.provenance.engineVersions.join(', ') || '—'}`],
    ['Report data SHA-256', r.integrity.dataSha256, true],
  ]));
  body.push(para([run('Observed facts (header values, hashes, indicators) are reported separately from analytical findings and from third-party intelligence. Network indicators are defanged. The data hash identifies the machine-readable JSON rendering of this same report.', { size: 17, color: MUTED, italics: true })], { spacingAfter: 200 }));
  body.push(new Paragraph({ children: [new PageBreak()] }));

  body.push(h('1. Summary', HeadingLevel.HEADING_1));
  body.push(
    table(['Measure', 'Count'], [
      ['Evidence files received (rejected / duplicate)', `${s.evidenceFiles} (${s.rejectedFiles} / ${s.duplicateFiles})`],
      ['Messages analysed / failed / pending', `${s.analyzed} / ${s.failed} / ${s.pending}`],
      ...Object.entries(s.byClass).map(([k, v]): [string, string] => [`Classified ${k}`, String(v)]),
      ['Messages with intelligence matches', String(s.withIntelMatches)],
      ['Campaign clusters (threat clusters)', `${s.clusters} (${s.threatClusters})`],
      ['Reported external campaign associations', String(s.externalAssociations)],
    ], [70, 30]),
  );

  body.push(h('2. Evidence received', HeadingLevel.HEADING_1));
  body.push(table(['File', 'Format', 'Bytes', 'SHA-256', 'Received / by', 'Status'], r.evidence.map((e) => [e.originalName.slice(0, 80), e.format ?? '—', String(e.size), e.sha256 ?? '—', `${e.receivedAt.slice(0, 19)} / ${e.uploadedBy ?? '—'}`, e.status + (e.error ? `: ${e.error.code}` : '')]), [22, 8, 8, 34, 18, 10], [3]));

  body.push(h('3. Messages requiring attention', HeadingLevel.HEADING_1));
  const attention = r.messages.filter((m) => ['malicious', 'suspicious', 'inconclusive'].includes(m.classification?.class ?? ''));
  if (!attention.length) body.push(para('No message in this scope was classified malicious, suspicious or inconclusive.'));
  for (const m of attention) body.push(...messageSection(m));
  const benign = r.messages.filter((m) => m.classification?.class === 'benign');
  if (benign.length) {
    body.push(h(`3.1 Benign messages (${benign.length})`, HeadingLevel.HEADING_2));
    body.push(table(['Subject', 'From', 'Risk', 'Coverage', 'Confidence'], benign.map((m) => [clean(m.summary.subject ?? '(no subject)', 90), m.summary.from ? defang(m.summary.from) : '—', String(m.classification?.riskScore ?? '—'), m.classification?.evidenceCoverage !== null && m.classification?.evidenceCoverage !== undefined ? `${Math.round(m.classification.evidenceCoverage * 100)}%` : '—', m.classification?.confidence ?? '—']), [42, 30, 8, 10, 10], [1]));
  }
  const other = r.messages.filter((m) => !m.classification || m.status === 'failed');
  if (other.length) {
    body.push(h(`3.2 Not analysed (${other.length})`, HeadingLevel.HEADING_2));
    body.push(table(['Message', 'Status', 'Detail'], other.map((m) => [m.id, m.status, m.duplicateOf ? `duplicate of ${m.duplicateOf}` : m.error ? `${m.error.code}: ${m.error.detail ?? ''}` : '—']), [30, 15, 55], [0]));
  }

  body.push(h('4. Campaign correlation (analytical inference)', HeadingLevel.HEADING_1));
  if (!r.campaigns.clusters.length) body.push(para('No clusters of related messages were found in this scope.'));
  for (const c of r.campaigns.clusters) {
    body.push(h(`${c.id} · ${c.label}`, HeadingLevel.HEADING_2));
    body.push(para(`${c.size} messages · verdict ${c.verdict} · confidence ${c.confidence} · cohesion ${c.cohesion} · density ${c.density} · ${c.exactRelationships} exact relationship(s) · first seen ${c.firstSeen?.slice(0, 10) ?? '—'} · last seen ${c.lastSeen?.slice(0, 10) ?? '—'}`));
    if (c.invariants.length) body.push(para(`Stayed constant: ${c.invariants.map((i) => i.attribute).join(', ')}`, { bullet: true }));
    if (c.rotated.length) body.push(para(`Rotated: ${c.rotated.map((i) => i.attribute).join(', ')}`, { bullet: true }));
    if (c.sharedIndicators.length) body.push(table(['Shared artifact', 'Value', 'Messages', 'Strength'], c.sharedIndicators.slice(0, 12).map((x) => [x.family, ind(x.type, x.value).slice(0, 140), String(x.messages), String(x.strength)]), [20, 56, 12, 12], [1]));
    for (const x of c.externalAssociations) body.push(para(`External: ${x.source} “${x.name}” (${x.assessment}, ${x.confidence} confidence, ${x.overlap} messages)`, { bullet: true }));
  }

  body.push(h('5. External campaign associations (third-party records)', HeadingLevel.HEADING_1));
  if (!r.campaigns.external.length) body.push(para('No message in this scope shares indicators with an externally documented campaign or event in the configured sources. This is not evidence that the messages are benign.'));
  for (const x of r.campaigns.external) {
    body.push(h(x.name, HeadingLevel.HEADING_2));
    body.push(para(`Source ${x.source} · event ${x.eventId} · ${x.organisation ?? '—'} · ${x.date?.slice(0, 10) ?? '—'} · ${x.assessment} (${x.confidence} confidence)`));
    if (x.reference) body.push(para([run('Reference: '), run(defang(x.reference), { mono: true })]));
    for (const rr of x.rationale) body.push(para(rr, { bullet: true }));
    body.push(table(['Type', 'Value', 'Match', 'Strength'], x.matchedIndicators.slice(0, 15).map((i) => [i.type, ind(i.type, i.value).slice(0, 140), i.matchType, i.strength === 0 ? '0 (not counted)' : String(i.strength)]), [12, 58, 18, 12], [1]));
  }

  body.push(h('6. Intelligence sources consulted', HeadingLevel.HEADING_1));
  body.push(table(['Source', 'Provider', 'Kind / attribution', 'Status', 'Last update', 'Records'], r.provenance.intelligenceSources.map((x) => [x.name, x.provider, `${x.kind} / ${x.attribution}`, x.status, x.lastSuccess?.slice(0, 19) ?? '—', String(x.records + x.events)]), [22, 22, 18, 12, 16, 10]));
  if (r.provenance.onlineLookups.length) {
    body.push(para([run('Online lookups performed (indicator disclosed to the listed services)', { bold: true })]));
    for (const l of r.provenance.onlineLookups) body.push(para(`${l.at} by ${l.by ?? '—'}: ${l.indicator}`, { bullet: true }));
  }

  body.push(h('7. Provenance', HeadingLevel.HEADING_1));
  body.push(kv([
    ['Engine versions', r.provenance.engineVersions.join(', ') || '—'],
    ['Configuration hashes', r.provenance.configHashes.join(', ') || '—', true],
    ['Intelligence snapshots', r.provenance.intelSnapshots.join(', ') || '—', true],
    ['Correlation', `${r.provenance.correlation.method} (run ${r.provenance.correlation.correlatedAt ?? '—'}, version ${r.provenance.correlation.version})`],
  ]));

  body.push(h('8. Limitations', HeadingLevel.HEADING_1));
  for (const l of r.limitations) body.push(para(l, { bullet: true }));
  body.push(para([run(`Report ${r.report.id} · data SHA-256 ${r.integrity.dataSha256}. ${r.integrity.note}`, { size: 15, color: MUTED })], { spacingAfter: 0 }));

  const doc = new Document({
    creator: 'MailShark Forensic Platform',
    title: `Forensic report: ${clean(r.case.name, 200)}`,
    description: `Report ${r.report.id}`,
    styles: { default: { document: { run: { font: FONT, size: 20, color: INK } } } },
    sections: [
      {
        properties: { page: { margin: { top: 1000, bottom: 1000, left: 1000, right: 1000 } } },
        headers: { default: new Header({ children: [new Paragraph({ alignment: AlignmentType.RIGHT, children: [run(`MailShark Forensic Platform · ${clean(r.case.name, 80)} · CONFIDENTIAL`, { size: 14, color: MUTED })] })] }) },
        footers: {
          default: new Footer({
            children: [
              new Paragraph({
                alignment: AlignmentType.CENTER,
                children: [
                  new TextRun({ text: `Report ${r.report.id} · page `, font: FONT, size: 14, color: MUTED }),
                  new TextRun({ children: [PageNumber.CURRENT], font: FONT, size: 14, color: MUTED }),
                  new TextRun({ text: ' of ', font: FONT, size: 14, color: MUTED }),
                  new TextRun({ children: [PageNumber.TOTAL_PAGES], font: FONT, size: 14, color: MUTED }),
                ],
              }),
            ],
          }),
        },
        children: body,
      },
    ],
  });
  return Packer.toBuffer(doc);
}
