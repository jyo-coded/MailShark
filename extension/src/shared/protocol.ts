// Messages between the Gmail overlay, extension pages and the background engine host.
import type { Confidence, LinkAnalysis, Report, Severity, Verdict } from '../../../engine/src/types';
import type { CampaignProfile } from '../../../engine/src/campaign/cluster';
import { ext } from './ext';

export type Source = 'gmail' | 'file';

export interface ReportMeta {
  source: Source;
  messageId: string | null;
  threadId: string | null;
  fileName: string | null;
  storedAt: number;
  clusterId: string | null;
}

export interface StoredReport {
  id: string;
  report: Report;
  meta: ReportMeta;
}

export interface CampaignBrief {
  id: string;
  label: string;
  size: number;
  verdict: Verdict;
  maxScore: number;
}

export interface GuardLink {
  url: string;
  host: string;
  regDomain: string | null;
  displayText: string | null;
  flags: string[];
  risk: LinkAnalysis['risk'];
  lookalikeOf: string | null;
  intelHit: string | null;
}

export interface ReportSummary {
  id: string;
  verdict: Verdict;
  score: number;
  confidence: Confidence;
  headline: string;
  oneLiner: string;
  subject: string;
  fromName: string;
  fromAddress: string;
  date: string | null;
  storedAt: number;
  source: Source;
  messageId: string | null;
  threadId: string | null;
  fileName: string | null;
  top: { id: string; title: string; severity: Severity; weight: number }[];
  counts: { links: number; riskyLinks: number; attachments: number; riskyAttachments: number; findings: number };
  auth: { spf: string; dkim: string; dmarc: string };
  campaign: CampaignBrief | null;
  guardLinks: GuardLink[];
  intent: string | null;
  brand: string | null;
}

export interface CampaignRecord {
  id: string;
  label: string;
  members: string[];
  createdAt: number;
  updatedAt: number;
  maxScore: number;
  verdict: Verdict;
  verdictCounts: Record<Verdict, number>;
  intent: string | null;
  brand: string | null;
  profile: CampaignProfile;
}

export interface Stats {
  total: number;
  danger: number;
  caution: number;
  safe: number;
  campaigns: number;
  threatCampaigns: number;
  since: number | null;
  today: { total: number; danger: number; caution: number };
  brands: { id: string; count: number }[];
  intents: { id: string; count: number }[];
}

export interface FeedStatus {
  enabled: boolean;
  entries: number;
  lists: { name: string; count: number; updated: string | null }[];
  lastCheck: number | null;
  lastSuccess: number | null;
  error: string | null;
}

export type Request =
  | { kind: 'analyze'; raw: string; meta: { source: Source; messageId: string | null; threadId: string | null; fileName: string | null }; force?: boolean }
  | { kind: 'summaries'; messageIds: string[] }
  | { kind: 'report'; id: string }
  | { kind: 'campaign'; id: string }
  | { kind: 'campaigns' }
  | { kind: 'history'; limit: number; offset: number; verdict?: Verdict | 'all'; query?: string }
  | { kind: 'stats' }
  | { kind: 'feedStatus' }
  | { kind: 'refreshFeeds' }
  | { kind: 'deleteReport'; id: string }
  | { kind: 'deleteAll' }
  | { kind: 'exportAll' }
  | { kind: 'openLab'; route?: string };

export type Response<K extends Request['kind']> = K extends 'analyze'
  ? { ok: true; summary: ReportSummary } | { ok: false; error: string }
  : K extends 'summaries'
    ? Record<string, ReportSummary>
    : K extends 'report'
      ? StoredReport | null
      : K extends 'campaign'
        ? { campaign: CampaignRecord; members: ReportSummary[] } | null
        : K extends 'campaigns'
          ? CampaignRecord[]
          : K extends 'history'
            ? { items: ReportSummary[]; total: number }
            : K extends 'stats'
              ? Stats
              : K extends 'feedStatus' | 'refreshFeeds'
                ? FeedStatus
                : K extends 'exportAll'
                  ? { json: string }
                  : { ok: boolean };

export async function send<R extends Request>(req: R): Promise<Response<R['kind']>> {
  return (await ext.runtime.sendMessage(req)) as Response<R['kind']>;
}

// Messages from the popup to the Gmail tab.
export type TabRequest = { kind: 'tab:openDissector' } | { kind: 'tab:active' };

export function summarize(stored: StoredReport, campaign: CampaignBrief | null): ReportSummary {
  const r = stored.report;
  const positives = r.findings.filter((f) => f.weight > 0 || f.weight < 0);
  return {
    id: r.id,
    verdict: r.verdict,
    score: r.score,
    confidence: r.confidence,
    headline: r.headline,
    oneLiner: r.oneLiner,
    subject: r.summary.subject,
    fromName: r.summary.from?.name ?? '',
    fromAddress: r.summary.from?.address ?? '',
    date: r.summary.date,
    storedAt: stored.meta.storedAt,
    source: stored.meta.source,
    messageId: stored.meta.messageId,
    threadId: stored.meta.threadId,
    fileName: stored.meta.fileName,
    top: positives.slice(0, 5).map((f) => ({ id: f.id, title: f.title, severity: f.severity, weight: f.weight })),
    counts: {
      links: r.links.length,
      riskyLinks: r.links.filter((l) => l.risk >= 2).length,
      attachments: r.attachments.filter((a) => !a.inline).length,
      riskyAttachments: r.attachments.filter((a) => a.risk >= 2).length,
      findings: r.findings.filter((f) => f.weight > 0).length,
    },
    auth: { spf: r.auth.spf, dkim: r.auth.dkim, dmarc: r.auth.dmarc },
    campaign,
    guardLinks: r.links
      .filter((l) => l.risk >= 2 || l.flags.includes('text-href-mismatch'))
      .slice(0, 60)
      .map((l) => ({ url: l.url, host: l.host, regDomain: l.regDomain, displayText: l.displayText, flags: l.flags, risk: l.risk, lookalikeOf: l.lookalikeOf, intelHit: l.intelHit })),
    intent: r.content.intent,
    brand: r.sender.impersonatedBrand ?? r.sender.verifiedBrand ?? null,
  };
}
