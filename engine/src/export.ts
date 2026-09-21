// Evidence exports: STIX 2.1 bundle (for MISP/OpenCTI/TAXII), IOC CSV and a Markdown case report.
import type { Report } from './types';
import { hash53 } from './util/hash';

function uuidFrom(seed: string): string {
  const h = (hash53(seed) + hash53(seed, 1) + hash53(seed, 2)).slice(0, 32).padEnd(32, '0');
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-5${h.slice(13, 16)}-8${h.slice(17, 20)}-${h.slice(20, 32)}`;
}

function defang(s: string): string {
  return s.replace(/^http/i, 'hxxp').replace(/\./g, '[.]');
}

export function toStixBundle(r: Report): object {
  const now = r.analyzedAt;
  const objs: Record<string, unknown>[] = [];
  const identity = { type: 'identity', spec_version: '2.1', id: `identity--${uuidFrom('mailshark')}`, created: now, modified: now, name: 'MailShark', identity_class: 'system' };
  objs.push(identity);
  const msgId = `email-message--${uuidFrom(r.id)}`;
  const refs: string[] = [];
  if (r.sender.from) {
    const addrId = `email-addr--${uuidFrom(r.sender.from.address)}`;
    objs.push({ type: 'email-addr', spec_version: '2.1', id: addrId, value: r.sender.from.address, display_name: r.sender.from.name || undefined });
    refs.push(addrId);
  }
  const fileRefs: string[] = [];
  for (const a of r.attachments.filter((x) => !x.inline)) {
    const id = `file--${uuidFrom(a.sha256)}`;
    objs.push({ type: 'file', spec_version: '2.1', id, name: a.filename, size: a.size, hashes: { 'SHA-256': a.sha256, 'SHA-1': a.sha1, MD5: a.md5 } });
    fileRefs.push(id);
  }
  objs.push({
    type: 'email-message', spec_version: '2.1', id: msgId, is_multipart: r.structure.partCount > 1, subject: r.summary.subject,
    date: r.summary.date ?? undefined, from_ref: refs[0], message_id: r.summary.messageId ?? undefined,
  });
  const indicators: string[] = [];
  const addIndicator = (pattern: string, name: string): void => {
    const id = `indicator--${uuidFrom(pattern)}`;
    indicators.push(id);
    objs.push({ type: 'indicator', spec_version: '2.1', id, created: now, modified: now, created_by_ref: identity.id, name, pattern, pattern_type: 'stix', valid_from: now, indicator_types: ['malicious-activity'], confidence: r.score });
  };
  if (r.verdict !== 'safe') {
    for (const l of r.links.filter((x) => x.risk >= 2 && x.host)) addIndicator(`[url:value = '${l.url.replace(/'/g, "\\'")}']`, `Suspicious URL (${l.flags.join(', ')})`);
    for (const a of r.attachments.filter((x) => x.risk >= 2)) addIndicator(`[file:hashes.'SHA-256' = '${a.sha256}']`, `Suspicious attachment ${a.filename}`);
    if (r.route.originIp) addIndicator(`[${r.route.originIp.includes(':') ? 'ipv6-addr' : 'ipv4-addr'}:value = '${r.route.originIp}']`, 'Sending IP');
    if (r.sender.from && (r.sender.impersonatedBrand || r.sender.lookalikeOf)) addIndicator(`[email-addr:value = '${r.sender.from.address}']`, 'Impersonating sender');
  }
  objs.push({
    type: 'report', spec_version: '2.1', id: `report--${uuidFrom('report' + r.id)}`, created: now, modified: now, created_by_ref: identity.id,
    name: `MailShark: ${r.headline}: ${r.summary.subject || '(no subject)'}`, published: now, report_types: ['threat-report'],
    description: `${r.headline} (risk ${r.score}/100, confidence ${r.confidence}). ${r.findings.filter((f) => f.weight > 0).slice(0, 6).map((f) => f.title).join('; ')}.`,
    object_refs: [msgId, ...refs, ...fileRefs, ...indicators],
  });
  return { type: 'bundle', id: `bundle--${uuidFrom('bundle' + r.id)}`, objects: objs };
}

export function toIocCsv(r: Report): string {
  const rows: string[][] = [['type', 'value', 'context']];
  const esc = (s: string): string => (/[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s);
  if (r.sender.from) rows.push(['email', r.sender.from.address, 'From']);
  for (const x of r.sender.replyTo) rows.push(['email', x.address, 'Reply-To']);
  if (r.route.originIp) rows.push(['ip', r.route.originIp, `Origin ${r.route.originHost ?? ''}`.trim()]);
  for (const l of r.links) rows.push(['url', l.url, l.flags.join(' ')]);
  for (const a of r.attachments) rows.push(['sha256', a.sha256, a.filename]);
  return rows.map((row) => row.map(esc).join(',')).join('\n');
}

export function toMarkdown(r: Report): string {
  const lines: string[] = [];
  lines.push(`# MailShark forensic report`);
  lines.push('');
  lines.push(`**Verdict:** ${r.headline} (risk ${r.score}/100, confidence ${r.confidence})  `);
  lines.push(`**Subject:** ${r.summary.subject || '(no subject)'}  `);
  lines.push(`**From:** ${r.sender.from ? `${r.sender.from.name} <${r.sender.from.address}>` : 'n/a'}  `);
  lines.push(`**Date:** ${r.summary.date ?? 'n/a'}  `);
  lines.push(`**Evidence SHA-256:** \`${r.hashes.sha256}\`  `);
  lines.push(`**Analyzed:** ${r.analyzedAt} by MailShark engine ${r.engineVersion}`);
  lines.push('');
  lines.push('## Findings');
  for (const f of r.findings) {
    lines.push(`- **[${f.severity.toUpperCase()}] ${f.title}**: ${f.detail}`);
    for (const e of f.evidence ?? []) lines.push(`  - ${e.label}: \`${e.value}\``);
  }
  lines.push('');
  lines.push('## Authentication');
  lines.push(`SPF **${r.auth.spf}** · DKIM **${r.auth.dkim}** · DMARC **${r.auth.dmarc}** · ARC **${r.auth.arc}** (source: ${r.auth.source}${r.auth.authServId ? `, ${r.auth.authServId}` : ''})`);
  lines.push('');
  lines.push('## Delivery path (oldest → newest)');
  for (const h of r.route.hops) lines.push(`1. ${h.fromRdns ?? h.fromHost ?? '?'} ${h.fromIp ? `[${h.fromIp}]` : ''} → ${h.byHost ?? '?'} ${h.protocol ?? ''} ${h.trusted ? '(verified)' : '(claimed)'}`);
  lines.push('');
  lines.push('## Links');
  for (const l of r.links) lines.push(`- \`${defang(l.url)}\`${l.flags.length ? ` (${l.flags.join(', ')})` : ''}`);
  if (r.attachments.length) {
    lines.push('');
    lines.push('## Attachments');
    for (const a of r.attachments) lines.push(`- ${a.filename} (${a.detectedType}, ${a.size} bytes) SHA-256 \`${a.sha256}\`${a.flags.length ? `: ${a.flags.join(', ')}` : ''}`);
  }
  lines.push('');
  lines.push('> URLs are defanged. Generated locally by MailShark; the original message never left this device.');
  return lines.join('\n');
}
