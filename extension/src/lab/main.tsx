// MailShark Lab: the analyst's workspace (overview, campaigns, history, file analysis, academy, settings).
import { render, type ComponentChildren } from 'preact';
import { useCallback, useEffect, useState } from 'preact/hooks';
import { VERSION } from '../shared/ext';
import { send, type CampaignRecord, type ReportSummary, type Stats, type StoredReport } from '../shared/protocol';
import { useSettings } from '../ui/theme';
import { SharkMark } from '../ui/SharkMark';
import { Dissector } from '../ui/dissector/Dissector';
import { BookOpen, GitFork, GraduationCap, History as HistoryIcon, Info, LayoutDashboard, Settings as SettingsIcon, ShieldCheck, Upload } from '../ui/icons';
import { OverviewPage } from './pages/Overview';
import { CampaignsPage } from './pages/Campaigns';
import { HistoryPage } from './pages/History';
import { AnalyzePage } from './pages/Analyze';
import { AcademyPage } from './pages/Academy';
import { SettingsPage } from './pages/Settings';
import { AboutPage } from './pages/About';
import { go, parseHash, type LabContext, type Route } from './nav';

function Reader({ id, onClose, onOpen }: { id: string; onClose: () => void; onOpen: (id: string) => void }) {
  const [data, setData] = useState<{ stored: StoredReport; campaign: { campaign: CampaignRecord; members: ReportSummary[] } | null } | null | undefined>(undefined);
  useEffect(() => {
    let alive = true;
    void (async () => {
      const stored = await send({ kind: 'report', id });
      if (!stored) {
        if (alive) setData(null);
        return;
      }
      const campaign = stored.meta.clusterId ? await send({ kind: 'campaign', id: stored.meta.clusterId }) : null;
      if (alive) setData({ stored, campaign });
    })();
    const onKey = (e: KeyboardEvent): void => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKey);
    return () => {
      alive = false;
      window.removeEventListener('keydown', onKey);
    };
  }, [id, onClose]);
  return (
    <div class="ms-reader" onClick={onClose}>
      <div class="ms-reader-panel" onClick={(e) => e.stopPropagation()} role="dialog" aria-modal="true" aria-label="Dissector">
        {data === undefined ? (
          <div style={{ height: '100%', display: 'grid', placeItems: 'center' }}>
            <SharkMark size={56} state="scan" />
          </div>
        ) : data === null ? (
          <div class="ms-empty">
            <div class="ms-h3">This report no longer exists</div>
          </div>
        ) : (
          <Dissector stored={data.stored} campaign={data.campaign} onClose={onClose} onOpenReport={onOpen} />
        )}
      </div>
    </div>
  );
}

const NAV: { page: Route['page']; label: string; icon: ComponentChildren }[] = [
  { page: 'overview', label: 'Overview', icon: <LayoutDashboard /> },
  { page: 'campaigns', label: 'Campaigns', icon: <GitFork /> },
  { page: 'history', label: 'Mail history', icon: <HistoryIcon /> },
  { page: 'analyze', label: 'Analyze files', icon: <Upload /> },
  { page: 'academy', label: 'Academy', icon: <GraduationCap /> },
];

function Lab() {
  const [settings] = useSettings();
  const [route, setRoute] = useState<Route>(parseHash());
  const [reader, setReader] = useState<string | null>(null);
  const [stats, setStats] = useState<Stats | null>(null);
  const refreshStats = useCallback(() => void send({ kind: 'stats' }).then(setStats), []);
  useEffect(() => {
    const onHash = (): void => setRoute(parseHash());
    window.addEventListener('hashchange', onHash);
    refreshStats();
    return () => window.removeEventListener('hashchange', onHash);
  }, [refreshStats]);
  useEffect(() => {
    const titles: Record<Route['page'], string> = { overview: 'Overview', campaigns: 'Campaigns', history: 'Mail history', analyze: 'Analyze files', academy: 'Academy', settings: 'Settings', about: 'About' };
    document.title = `${titles[route.page]} · MailShark Lab`;
  }, [route.page]);
  const closeReader = useCallback(() => setReader(null), []);
  const ctx: LabContext = { openReport: setReader, stats, refreshStats };
  const threatCount = stats ? stats.threatCampaigns : 0;

  return (
    <div class="ms-lab">
      <div class="ms-sea" />
      <aside class="ms-side">
        <div class="ms-side-brand">
          <SharkMark size={34} state="idle" />
          <div>
            <div class="ms-wordmark">MailShark</div>
            <div class="ms-faint" style={{ fontSize: '11.5px' }}>
              Lab · v{VERSION}
            </div>
          </div>
        </div>
        <nav class="ms-nav" aria-label="Lab">
          {NAV.map((n) => (
            <button type="button" class="ms-nav-item" aria-current={route.page === n.page ? 'page' : undefined} onClick={() => go(n.page)}>
              {n.icon}
              {n.label}
              {n.page === 'campaigns' && threatCount > 0 && <span class="ms-nav-badge">{threatCount}</span>}
            </button>
          ))}
          <div class="ms-nav-sep" />
          <button type="button" class="ms-nav-item" aria-current={route.page === 'settings' ? 'page' : undefined} onClick={() => go('settings')}>
            <SettingsIcon />
            Settings
          </button>
          <button type="button" class="ms-nav-item" aria-current={route.page === 'about' ? 'page' : undefined} onClick={() => go('about')}>
            <Info />
            Privacy & about
          </button>
        </nav>
        <div class="ms-side-foot">
          <div class="ms-guardian">
            <b>
              <ShieldCheck size={15} color={settings.protection ? 'var(--ms-safe)' : 'var(--ms-text-3)'} />
              {settings.protection ? 'Guarding Gmail' : 'Protection paused'}
            </b>
            Every analysis runs on this device. Nothing is uploaded.
          </div>
          <a class="ms-btn ms-btn--ghost ms-btn--sm" href="https://github.com/jyo-coded/MailShark" target="_blank" rel="noopener noreferrer">
            <BookOpen /> Documentation
          </a>
        </div>
      </aside>
      <main class="ms-main">
        <div class="ms-main-inner" key={route.page}>
          {route.page === 'overview' && <OverviewPage ctx={ctx} />}
          {route.page === 'campaigns' && <CampaignsPage ctx={ctx} selected={route.arg} />}
          {route.page === 'history' && <HistoryPage ctx={ctx} />}
          {route.page === 'analyze' && <AnalyzePage ctx={ctx} />}
          {route.page === 'academy' && <AcademyPage ctx={ctx} />}
          {route.page === 'settings' && <SettingsPage ctx={ctx} />}
          {route.page === 'about' && <AboutPage />}
        </div>
      </main>
      {reader && <Reader id={reader} onClose={closeReader} onOpen={setReader} />}
    </div>
  );
}

render(<Lab />, document.getElementById('app') as HTMLElement);
