// Analysis pipeline: raw message → engine → campaign correlation → local evidence store.
import { analyzeEmail } from '../../../engine/src/analyze';
import { scoreFindings, sortFindings } from '../../../engine/src/score';
import { parseAddressList } from '../../../engine/src/analyzers/sender';
import type { Finding, Report, Verdict } from '../../../engine/src/types';
import { latin1ToBytes } from '../../../engine/src/util/text';
import { loadSettings, thresholds } from '../shared/settings';
import { summarize, type CampaignBrief, type ReportMeta, type ReportSummary, type Source, type StoredReport } from '../shared/protocol';
import { db, prune } from './db';
import { brief, correlate } from './campaigns';
import { getIntel } from './feeds';
import { qrDecoder } from './qr';

const HEADLINE: Record<Verdict, string> = { danger: 'Likely phishing', caution: 'Be careful', safe: 'Looks safe' };

function applyThresholds(report: Report, sensitivity: Parameters<typeof thresholds>[0]): void {
  const t = thresholds(sensitivity);
  const verdict: Verdict = report.score >= t.danger ? 'danger' : report.score >= t.caution ? 'caution' : 'safe';
  report.verdict = verdict;
  report.headline = HEADLINE[verdict];
}

function fromAddressOf(raw: string): string | null {
  const head = raw.slice(0, 64 * 1024);
  const m = /^From:[ \t]*((?:.*)(?:\r?\n[ \t]+.*)*)/im.exec(head);
  if (!m || !m[1]) return null;
  return parseAddressList(m[1].replace(/\r?\n[ \t]+/g, ' '))[0]?.address ?? null;
}

function campaignFinding(c: CampaignBrief, report: Report): Finding | null {
  if (c.size < 2) return null;
  if (c.verdict === 'danger' && report.verdict !== 'danger') {
    return {
      id: 'campaign.known-threat', category: 'campaign', severity: 'high', weight: 1.6,
      title: `Part of a known phishing campaign (${c.id})`,
      detail: `This email shares its template and infrastructure with ${c.size - 1} other message${c.size > 2 ? 's' : ''} already judged dangerous.`,
      evidence: [{ label: 'Campaign', value: `${c.id} · ${c.label}` }],
    };
  }
  return {
    id: 'campaign.member', category: 'campaign', severity: 'info', weight: 0,
    title: `Part of campaign ${c.id} (${c.size} emails)`,
    detail: c.verdict === 'safe' ? 'A recurring bulk mailing: same template and sending setup.' : `Linked to ${c.size - 1} similar message${c.size > 2 ? 's' : ''} despite rotated senders or links.`,
    evidence: [{ label: 'Campaign', value: `${c.id} · ${c.label}` }],
  };
}

export async function analyzeAndStore(
  raw: string,
  meta: { source: Source; messageId: string | null; threadId: string | null; fileName: string | null },
  force = false,
): Promise<ReportSummary> {
  const d = await db();
  if (!force && meta.messageId) {
    const existing = await d.getFromIndex('reports', 'messageId', meta.messageId);
    if (existing) return summaryOf(existing);
  }

  const settings = await loadSettings();
  const bytes = latin1ToBytes(raw);
  const fromAddr = fromAddressOf(raw);
  const senderRow = fromAddr ? await d.get('senders', fromAddr) : undefined;
  const report = await analyzeEmail(bytes, {
    context: { senderSeenCount: senderRow?.count ?? 0 },
    intel: await getIntel(),
    qrDecoder,
  });
  const previous = await d.get('reports', report.id);
  // Re-analysing the exact same message must not count it as a second sighting of the sender.
  if (previous) {
    report.findings = report.findings.filter((f) => f.id !== 'sender.first-time' && f.id !== 'sender.known');
    const rescored = scoreFindings(report.findings, report.auth.source, report.content.textPreview.length);
    Object.assign(report, rescored);
  }
  applyThresholds(report, settings.sensitivity);

  const storedAt = Date.now();
  const time = report.fingerprint.time || storedAt;
  const campaign = await correlate({ id: report.id, clusterId: previous?.meta.clusterId ?? null, fp: report.fingerprint, score: report.score, verdict: report.verdict, time });
  if (campaign) {
    const cf = campaignFinding(campaign, report);
    if (cf) {
      report.findings = sortFindings([...report.findings.filter((f) => f.category !== 'campaign'), cf]);
      Object.assign(report, scoreFindings(report.findings, report.auth.source, report.content.textPreview.length));
      applyThresholds(report, settings.sensitivity);
      const member = await d.get('members', report.id);
      if (member) await d.put('members', { ...member, score: report.score, verdict: report.verdict });
    }
  }

  const stored: StoredReport = {
    id: report.id,
    report,
    meta: {
      source: meta.source,
      messageId: meta.messageId ?? previous?.meta.messageId ?? null,
      threadId: meta.threadId ?? previous?.meta.threadId ?? null,
      fileName: meta.fileName ?? previous?.meta.fileName ?? null,
      storedAt: previous?.meta.storedAt ?? storedAt,
      clusterId: campaign?.id ?? null,
    } satisfies ReportMeta,
  };
  await d.put('reports', stored);
  if (fromAddr && !previous) {
    await d.put('senders', {
      address: fromAddr,
      count: (senderRow?.count ?? 0) + 1,
      firstSeen: senderRow?.firstSeen ?? storedAt,
      lastSeen: storedAt,
    });
  }
  if (Math.random() < 0.05) void prune();
  if (campaign) {
    const c = await d.get('campaigns', campaign.id);
    return summarize(stored, c ? brief(c) : campaign);
  }
  return summarize(stored, null);
}

export async function summaryOf(stored: StoredReport): Promise<ReportSummary> {
  let c: CampaignBrief | null = null;
  if (stored.meta.clusterId) {
    const rec = await (await db()).get('campaigns', stored.meta.clusterId);
    if (rec) c = brief(rec);
  }
  return summarize(stored, c);
}
