// Toolbar popup: protection status, the email on screen, quick switches.
import { render } from 'preact';
import { useEffect, useState } from 'preact/hooks';
import { ext, VERSION } from '../shared/ext';
import { saveSettings } from '../shared/settings';
import { send, type FeedStatus, type ReportSummary, type Stats } from '../shared/protocol';
import { relativeTime } from '../shared/format';
import { useSettings } from '../ui/theme';
import { SharkMark } from '../ui/SharkMark';
import { ScoreRing } from '../ui/ScoreRing';
import { Switch } from '../ui/primitives';
import { ArrowRight, Inbox, LayoutDashboard, MousePointerClick, Radar, ScanEye, Settings as SettingsIcon, ShieldCheck } from '../ui/icons';

function Popup() {
  const [settings, ready] = useSettings();
  const [stats, setStats] = useState<Stats | null>(null);
  const [feed, setFeed] = useState<FeedStatus | null>(null);
  const [current, setCurrent] = useState<ReportSummary | null>(null);
  const [gmailTab, setGmailTab] = useState<number | null>(null);

  useEffect(() => {
    void send({ kind: 'stats' }).then(setStats);
    void send({ kind: 'feedStatus' }).then(setFeed);
    void ext.tabs.query({ active: true, currentWindow: true }).then(async ([tab]) => {
      if (tab?.id === undefined || !tab.url?.startsWith('https://mail.google.com/')) return;
      setGmailTab(tab.id);
      try {
        const s = (await ext.tabs.sendMessage(tab.id, { kind: 'tab:active' })) as ReportSummary | null;
        setCurrent(s);
      } catch {
        /* Gmail tab opened before install: content script not present yet */
      }
    });
  }, []);

  const openLab = (route?: string): void => {
    void send({ kind: 'openLab', ...(route ? { route } : {}) }).then(() => window.close());
  };
  const threats = stats ? stats.danger + stats.caution : 0;

  return (
    <div class="ms-popup">
      <div class="ms-sea" />
      <header class="ms-popup-head">
        <SharkMark size={30} state="idle" />
        <div class="ms-wordmark">
          MailShark <span>v{VERSION}</span>
        </div>
        <div class="ms-grow" />
        <button type="button" class="ms-btn ms-btn--ghost ms-btn--sm ms-btn--icon" aria-label="Settings" data-tip="Settings" onClick={() => openLab('settings')}>
          <SettingsIcon />
        </button>
      </header>

      <div class="ms-popup-body">
        <div class="ms-status" data-off={settings.protection ? undefined : ''}>
          <SharkMark size={44} state={settings.protection ? 'scan' : 'idle'} still={!settings.protection} />
          <div style={{ minWidth: 0 }}>
            <h2>{settings.protection ? 'Protection is on' : 'Protection is paused'}</h2>
            <p>{gmailTab !== null ? 'Watching this Gmail tab · 100% on-device' : 'Open Gmail: every email you read gets dissected.'}</p>
          </div>
          {ready && <Switch checked={settings.protection} label="Protection" onChange={(v) => void saveSettings({ protection: v })} />}
        </div>

        {current && (
          <div class="ms-current" style={{ animation: 'ms-fade-up 320ms var(--ms-ease-out) both' }}>
            <ScoreRing score={current.score} verdict={current.verdict} size={52} stroke={5} />
            <div style={{ minWidth: 0 }}>
              <div class="ms-row" style={{ justifyContent: 'space-between' }}>
                <b style={{ color: `var(--ms-${current.verdict})`, fontSize: '14px' }}>{current.headline}</b>
                <button
                  type="button"
                  class="ms-btn ms-btn--primary ms-btn--sm"
                  onClick={() => {
                    if (gmailTab !== null) void ext.tabs.sendMessage(gmailTab, { kind: 'tab:openDissector' }).then(() => window.close());
                  }}
                >
                  <ScanEye /> Dissect
                </button>
              </div>
              <div class="ms-truncate" style={{ fontSize: '12.5px', marginTop: '2px' }}>
                {current.subject || '(no subject)'}
              </div>
              <div class="ms-truncate ms-faint" style={{ fontSize: '12px' }}>
                {current.oneLiner}
              </div>
            </div>
          </div>
        )}

        <div class="ms-stats">
          <div class="ms-stat">
            <b>{stats?.total.toLocaleString() ?? '—'}</b>
            <span>emails dissected</span>
          </div>
          <div class="ms-stat" data-tone={threats ? 'danger' : undefined}>
            <b>{stats ? threats.toLocaleString() : '—'}</b>
            <span>threats caught</span>
          </div>
          <div class="ms-stat">
            <b>{stats?.campaigns.toLocaleString() ?? '—'}</b>
            <span>campaigns traced</span>
          </div>
        </div>

        <div class="ms-toggles">
          <div class="ms-toggle-row">
            <span class="ms-ti">
              <MousePointerClick />
            </span>
            <div>
              <b>Link guard</b>
              <small>Stop clicks on dangerous links</small>
            </div>
            <Switch checked={settings.linkGuard} label="Link guard" onChange={(v) => void saveSettings({ linkGuard: v })} />
          </div>
          <div class="ms-toggle-row">
            <span class="ms-ti">
              <Radar />
            </span>
            <div>
              <b>Inbox radar</b>
              <small>Verdict badges in your inbox list</small>
            </div>
            <Switch checked={settings.radar} label="Inbox radar" onChange={(v) => void saveSettings({ radar: v })} />
          </div>
        </div>

        <button type="button" class="ms-btn ms-btn--lg" style={{ width: '100%' }} onClick={() => openLab()}>
          <LayoutDashboard /> Open MailShark Lab <ArrowRight style={{ marginLeft: 'auto' }} />
        </button>
        {gmailTab === null && (
          <a class="ms-btn ms-btn--ghost" style={{ width: '100%' }} href="https://mail.google.com/" target="_blank" rel="noopener noreferrer">
            <Inbox /> Go to Gmail
          </a>
        )}
      </div>

      <footer class="ms-popup-foot">
        <span class="ms-row" style={{ gap: '6px' }}>
          <ShieldCheck size={13} />
          {feed?.enabled
            ? feed.entries
              ? `Threat intel: ${feed.entries.toLocaleString()} domains · ${relativeTime(feed.lastSuccess)}`
              : feed.error
                ? 'Threat intel: not downloaded yet'
                : 'Threat intel: updating…'
            : 'Threat intel: off'}
        </span>
        <span>On-device</span>
      </footer>
    </div>
  );
}

render(<Popup />, document.getElementById('app') as HTMLElement);
