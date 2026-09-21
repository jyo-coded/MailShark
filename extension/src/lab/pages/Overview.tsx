import { useEffect, useState } from 'preact/hooks';
import { sendOr, type CampaignRecord, type ReportSummary } from '../../shared/protocol';
import { formatDateTime, plural } from '../../shared/format';
import { brandById } from '../../../../engine/src/data/brands';
import { Empty } from '../../ui/primitives';
import { SharkMark } from '../../ui/SharkMark';
import { INTENT_LABELS } from '../../ui/labels';
import { Activity, ArrowRight, GitFork, Inbox, ScanEye, ShieldAlert, ShieldCheck, Target, Upload } from '../../ui/icons';
import { Kpi, MailRow, PageHead } from '../components';
import { go, type LabContext } from '../nav';
import { CampaignCard } from './Campaigns';

export function OverviewPage({ ctx }: { ctx: LabContext }) {
  const s = ctx.stats;
  const [threats, setThreats] = useState<ReportSummary[] | null>(null);
  const [recent, setRecent] = useState<ReportSummary[] | null>(null);
  const [campaigns, setCampaigns] = useState<CampaignRecord[] | null>(null);
  useEffect(() => {
    ctx.refreshStats();
    const none = { items: [], total: 0 };
    void sendOr({ kind: 'history', limit: 6, offset: 0, verdict: 'danger' }, none).then(async (d) => {
      const c = await sendOr({ kind: 'history', limit: 6, offset: 0, verdict: 'caution' }, none);
      setThreats([...d.items, ...c.items].sort((a, b) => b.storedAt - a.storedAt).slice(0, 7));
    });
    void sendOr({ kind: 'history', limit: 6, offset: 0 }, none).then((d) => setRecent(d.items));
    void sendOr({ kind: 'campaigns' }, []).then((c) => setCampaigns(c.slice(0, 3)));
  }, []);

  const hour = new Date().getHours();
  const greet = hour < 5 ? 'Late-night watch' : hour < 12 ? 'Good morning' : hour < 18 ? 'Good afternoon' : 'Good evening';
  const intentMax = Math.max(1, ...(s?.intents.map((i) => i.count) ?? [1]));

  return (
    <>
      <PageHead
        eyebrow={greet}
        title={
          <>
            Your inbox, <span class="ms-gradient-text">dissected.</span>
          </>
        }
        actions={
          <>
            <button type="button" class="ms-btn" onClick={() => go('analyze')}>
              <Upload /> Analyze a file
            </button>
            <a class="ms-btn ms-btn--primary" href="https://mail.google.com/" target="_blank" rel="noopener noreferrer">
              <Inbox /> Open Gmail
            </a>
          </>
        }
      >
        Every email you open in Gmail is taken apart on this device (headers, route, links, attachments, wording) and linked to the campaigns behind it.
      </PageHead>

      <div class="ms-grid ms-grid-4 ms-stagger">
        <Kpi icon={<ScanEye />} tone="accent" value={s?.total.toLocaleString() ?? '—'} label="Emails dissected" />
        <Kpi icon={<ShieldAlert />} tone="danger" value={s ? (s.danger + s.caution).toLocaleString() : '—'} label={s ? `Threats caught · ${s.danger} dangerous` : 'Threats caught'} />
        <Kpi icon={<GitFork />} tone="caution" value={s?.threatCampaigns.toLocaleString() ?? '—'} label={s ? `Threat campaigns · ${plural(s.campaigns, 'campaign')} total` : 'Threat campaigns'} />
        <Kpi icon={<ShieldCheck />} tone="safe" value={s?.today.total.toLocaleString() ?? '—'} label={s?.since ? `Today · guarding since ${formatDateTime(s.since).split(',')[0]}` : 'Dissected today'} />
      </div>

      <div class="ms-grid ms-grid-main" style={{ marginTop: '14px' }}>
        <div class="ms-panel">
          <div class="ms-panel-head">
            <span class="ms-h3">Recent threats</span>
            <button type="button" class="ms-btn ms-btn--ghost ms-btn--sm" onClick={() => go('history')}>
              All mail <ArrowRight />
            </button>
          </div>
          {threats === null ? (
            <div style={{ padding: '16px' }}>
              <div class="ms-skeleton" style={{ height: '46px' }} />
            </div>
          ) : threats.length ? (
            <div class="ms-list ms-stagger">{threats.map((t) => <MailRow s={t} onOpen={ctx.openReport} />)}</div>
          ) : (
            <Empty icon={<SharkMark size={52} state="safe" />} title="No threats so far">
              {recent && recent.length ? 'Everything MailShark has dissected looks clean.' : 'Open any email in Gmail and MailShark will dissect it instantly.'}
            </Empty>
          )}
        </div>

        <div class="ms-col" style={{ gap: '14px' }}>
          <div class="ms-panel">
            <div class="ms-panel-head">
              <span class="ms-h3">Threat mix</span>
              <Activity size={16} class="ms-faint" />
            </div>
            <div class="ms-panel-body">
              {s && s.intents.length ? (
                s.intents.slice(0, 6).map((i) => (
                  <div class="ms-intent">
                    <span style={{ fontSize: '13px' }}>{INTENT_LABELS[i.id] ?? i.id}</span>
                    <span class="ms-mono ms-faint" style={{ fontSize: '12px' }}>
                      {i.count}
                    </span>
                    <div class="ms-meter" data-tone="danger">
                      <span style={{ width: `${(i.count / intentMax) * 100}%` }} />
                    </div>
                  </div>
                ))
              ) : (
                <div class="ms-muted" style={{ fontSize: '13px' }}>
                  Lure types (credential theft, invoice fraud, delivery scams…) appear here once threats are caught.
                </div>
              )}
            </div>
          </div>
          <div class="ms-panel">
            <div class="ms-panel-head">
              <span class="ms-h3">Most impersonated</span>
              <Target size={16} class="ms-faint" />
            </div>
            <div class="ms-panel-body ms-col" style={{ gap: '8px' }}>
              {s && s.brands.length ? (
                s.brands.slice(0, 6).map((b) => (
                  <div class="ms-row" style={{ justifyContent: 'space-between' }}>
                    <span>{brandById(b.id)?.name ?? b.id}</span>
                    <span class="ms-chip ms-chip--danger">{plural(b.count, 'email')}</span>
                  </div>
                ))
              ) : (
                <div class="ms-muted" style={{ fontSize: '13px' }}>
                  No brand impersonation detected yet.
                </div>
              )}
            </div>
          </div>
        </div>
      </div>

      {campaigns && campaigns.length > 0 && (
        <>
          <div class="ms-row" style={{ justifyContent: 'space-between', margin: '26px 0 12px' }}>
            <span class="ms-h2">Traced campaigns</span>
            <button type="button" class="ms-btn ms-btn--ghost ms-btn--sm" onClick={() => go('campaigns')}>
              All campaigns <ArrowRight />
            </button>
          </div>
          <div class="ms-grid ms-grid-3 ms-stagger">
            {campaigns.map((c) => (
              <CampaignCard c={c} />
            ))}
          </div>
        </>
      )}
    </>
  );
}
