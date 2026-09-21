// The Dissector: header + verdict hero + layered tabs.
import { useEffect, useRef, useState } from 'preact/hooks';
import type { CampaignRecord, ReportSummary, StoredReport } from '../../shared/protocol';
import { SharkMark } from '../SharkMark';
import { ScoreRing } from '../ScoreRing';
import { Chip, Tabs, VerdictIcon, type TabDef } from '../primitives';
import { CodeXml, Fingerprint, GitFork, Globe, LayoutDashboard, Network, Paperclip, ScanEye, User, X } from '../icons';
import { CampaignPanel, ContentPanel, FilesPanel, LinksPanel, OverviewPanel, RoutePanel, SenderPanel, SourcePanel } from './panels';
import { relativeTime } from '../../shared/format';

export type DxTab = 'overview' | 'sender' | 'route' | 'links' | 'files' | 'content' | 'campaign' | 'source';

export interface DissectorProps {
  stored: StoredReport;
  campaign: { campaign: CampaignRecord; members: ReportSummary[] } | null;
  onClose?: () => void;
  onOpenReport?: (id: string) => void;
  onOpenLab?: () => void;
  initialTab?: DxTab;
}

export function Dissector({ stored, campaign, onClose, onOpenReport, onOpenLab, initialTab = 'overview' }: DissectorProps) {
  const r = stored.report;
  const [tab, setTab] = useState<DxTab>(initialTab);
  const scroller = useRef<HTMLDivElement>(null);
  useEffect(() => {
    scroller.current?.scrollTo({ top: 0 });
  }, [stored.id]);
  useEffect(() => setTab(initialTab), [stored.id, initialTab]);

  const riskyLinks = r.links.filter((l) => l.risk >= 2).length;
  const riskyFiles = r.attachments.filter((a) => a.risk >= 2).length;
  const tabs: TabDef<DxTab>[] = [
    { id: 'overview', label: 'Verdict', icon: <ScanEye />, count: r.findings.filter((f) => f.weight > 0).length, tone: r.verdict === 'safe' ? undefined : r.verdict },
    { id: 'sender', label: 'Sender', icon: <User /> },
    { id: 'route', label: 'Route', icon: <Network />, count: r.route.hops.length },
    { id: 'links', label: 'Links', icon: <Globe />, count: riskyLinks || r.links.length, tone: riskyLinks ? 'danger' : undefined },
    { id: 'files', label: 'Files', icon: <Paperclip />, count: riskyFiles || r.attachments.filter((a) => !a.inline).length, tone: riskyFiles ? 'danger' : undefined },
    { id: 'content', label: 'Content', icon: <Fingerprint /> },
    { id: 'campaign', label: 'Campaign', icon: <GitFork />, count: campaign?.campaign.members.length ?? 0 },
    { id: 'source', label: 'Source', icon: <CodeXml /> },
  ];

  const sharkState = r.verdict === 'danger' ? 'danger' : r.verdict === 'caution' ? 'caution' : 'safe';
  return (
    <div class="ms-dx" data-verdict={r.verdict}>
      <div class="ms-dx-scroll ms-scroll" ref={scroller} style={{ height: '100%' }}>
        <div class="ms-dx-head">
          <div class="ms-dx-brand">
            <SharkMark size={26} state={sharkState} />
            MailShark <span>Dissector</span>
          </div>
          <div class="ms-grow" />
          {onOpenLab && (
            <button type="button" class="ms-btn ms-btn--ghost ms-btn--sm" onClick={onOpenLab}>
              <LayoutDashboard /> Lab
            </button>
          )}
          {onClose && (
            <button type="button" class="ms-btn ms-btn--ghost ms-btn--sm ms-btn--icon" aria-label="Close" onClick={onClose}>
              <X />
            </button>
          )}
        </div>

        <div class="ms-dx-hero">
          <ScoreRing score={r.score} verdict={r.verdict} size={88} />
          <div style={{ minWidth: 0 }}>
            <h2 class="ms-dx-verdict">{r.headline}</h2>
            <p class="ms-dx-oneliner">{r.oneLiner}</p>
            <div class="ms-dx-meta">
              <Chip tone={r.verdict} icon={<VerdictIcon verdict={r.verdict} size={12} />}>
                {r.confidence} confidence
              </Chip>
              {campaign && (
                <button type="button" class="ms-chip ms-chip--accent" style={{ cursor: 'pointer' }} onClick={() => setTab('campaign')}>
                  <GitFork />
                  {campaign.campaign.id} · {campaign.campaign.members.length} emails
                </button>
              )}
              <Chip>
                SPF {r.auth.spf} · DKIM {r.auth.dkim} · DMARC {r.auth.dmarc}
              </Chip>
            </div>
            <div class="ms-dx-subject ms-truncate">
              <b>{r.summary.subject || '(no subject)'}</b> · {relativeTime(r.summary.date)}
            </div>
          </div>
        </div>

        <Tabs tabs={tabs} value={tab} onChange={setTab} />
        <div class="ms-dx-body" role="tabpanel">
          {tab === 'overview' && <OverviewPanel r={r} />}
          {tab === 'sender' && <SenderPanel r={r} />}
          {tab === 'route' && <RoutePanel r={r} />}
          {tab === 'links' && <LinksPanel r={r} />}
          {tab === 'files' && <FilesPanel r={r} />}
          {tab === 'content' && <ContentPanel r={r} />}
          {tab === 'campaign' && <CampaignPanel campaign={campaign?.campaign ?? null} members={campaign?.members ?? []} currentId={r.id} onOpen={onOpenReport} />}
          {tab === 'source' && <SourcePanel stored={stored} />}
        </div>
      </div>
    </div>
  );
}
