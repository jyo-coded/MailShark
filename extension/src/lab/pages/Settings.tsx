import type { ComponentChildren } from 'preact';
import { useEffect, useState } from 'preact/hooks';
import { saveSettings, type Settings } from '../../shared/settings';
import { send, type FeedStatus } from '../../shared/protocol';
import { plural, relativeTime } from '../../shared/format';
import { useSettings } from '../../ui/theme';
import { Segmented, Switch, download } from '../../ui/primitives';
import { Download, Monitor, Moon, RefreshCw, Sun, Trash2 } from '../../ui/icons';
import { PageHead } from '../components';
import type { LabContext } from '../nav';
import { FEED_BASE } from '../../shared/constants';

function Row({ title, desc, children }: { title: string; desc: string; children: ComponentChildren }) {
  return (
    <div class="ms-setting">
      <div>
        <b>{title}</b>
        <small>{desc}</small>
      </div>
      <div>{children}</div>
    </div>
  );
}

export function SettingsPage({ ctx }: { ctx: LabContext }) {
  const [s] = useSettings();
  const [feed, setFeed] = useState<FeedStatus | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const [confirmWipe, setConfirmWipe] = useState(false);
  useEffect(() => void send({ kind: 'feedStatus' }).then(setFeed), []);
  const set = (patch: Partial<Settings>): void => void saveSettings(patch);

  return (
    <>
      <PageHead eyebrow="Preferences" title="Settings">
        Tune how MailShark protects your inbox. Changes apply instantly in every open Gmail tab.
      </PageHead>

      <div class="ms-grid" style={{ gap: '14px', maxWidth: '860px' }}>
        <div class="ms-panel">
          <div class="ms-panel-head">
            <span class="ms-h3">Protection</span>
          </div>
          <Row title="Dissect emails automatically" desc="Analyse every email you open in Gmail.">
            <Switch checked={s.protection} label="Dissect emails automatically" onChange={(v) => set({ protection: v })} />
          </Row>
          <Row title="Link guard" desc="Stop clicks on dangerous links and show where they really lead.">
            <Switch checked={s.linkGuard} label="Link guard" onChange={(v) => set({ linkGuard: v })} />
          </Row>
          <Row title="Sensitivity" desc="Strict flags more borderline emails; relaxed only speaks up when it's sure.">
            <Segmented
              label="Sensitivity"
              value={s.sensitivity}
              onChange={(v) => set({ sensitivity: v })}
              options={[
                { value: 'relaxed', label: 'Relaxed' },
                { value: 'balanced', label: 'Balanced' },
                { value: 'strict', label: 'Strict' },
              ]}
            />
          </Row>
          <Row title="Safe emails" desc="How MailShark presents emails that look safe.">
            <Segmented
              label="Safe email banner"
              value={s.safeBanner}
              onChange={(v) => set({ safeBanner: v })}
              options={[
                { value: 'full', label: 'Full' },
                { value: 'compact', label: 'Compact' },
                { value: 'hidden', label: 'Hidden' },
              ]}
            />
          </Row>
        </div>

        <div class="ms-panel">
          <div class="ms-panel-head">
            <span class="ms-h3">Inbox radar</span>
          </div>
          <Row title="Verdict badges" desc="Show MailShark badges next to emails in the inbox list.">
            <Switch checked={s.radar} label="Verdict badges" onChange={(v) => set({ radar: v })} />
          </Row>
          <Row title="Scan unopened emails" desc="Dissect emails visible in your inbox before you open them (gently rate-limited).">
            <Switch checked={s.radarScan} label="Scan unopened emails" onChange={(v) => set({ radarScan: v })} />
          </Row>
        </div>

        <div class="ms-panel">
          <div class="ms-panel-head">
            <span class="ms-h3">Appearance</span>
          </div>
          <Row title="Lab & popup theme" desc="Follow your system or pick a side.">
            <Segmented
              label="Theme"
              value={s.theme}
              onChange={(v) => set({ theme: v })}
              options={[
                { value: 'system', label: 'System', icon: <Monitor /> },
                { value: 'dark', label: 'Dark', icon: <Moon /> },
                { value: 'light', label: 'Light', icon: <Sun /> },
              ]}
            />
          </Row>
          <Row title="Inside Gmail" desc="Auto matches your Gmail theme.">
            <Segmented
              label="Gmail overlay theme"
              value={s.overlayTheme}
              onChange={(v) => set({ overlayTheme: v })}
              options={[
                { value: 'auto', label: 'Auto' },
                { value: 'dark', label: 'Dark' },
                { value: 'light', label: 'Light' },
              ]}
            />
          </Row>
        </div>

        <div class="ms-panel">
          <div class="ms-panel-head">
            <span class="ms-h3">Threat intelligence</span>
          </div>
          <Row title="Public threat feeds" desc="Download phishing & malware domain lists and check links locally. No data about your mail is sent.">
            <Switch checked={s.feeds} label="Public threat feeds" onChange={(v) => set({ feeds: v })} />
          </Row>
          <div class="ms-setting">
            <div>
              <b>
                {feed?.entries ? `${feed.entries.toLocaleString()} known-bad domains on device` : 'Feeds not downloaded yet'}
              </b>
              <small>
                {feed?.lists.length ? feed.lists.map((l) => `${l.name} (${plural(l.count, 'entry', 'entries')})`).join(' · ') : `Source: ${FEED_BASE}`}
                {feed?.lastSuccess ? ` · updated ${relativeTime(feed.lastSuccess)}` : ''}
                {feed?.error ? ` · last attempt: ${feed.error}` : ''}
              </small>
            </div>
            <button
              type="button"
              class="ms-btn ms-btn--sm"
              disabled={!s.feeds || refreshing}
              onClick={() => {
                setRefreshing(true);
                void send({ kind: 'refreshFeeds' })
                  .then(setFeed)
                  .finally(() => setRefreshing(false));
              }}
            >
              <RefreshCw style={refreshing ? { animation: 'ms-spin 1s linear infinite' } : undefined} /> Update now
            </button>
          </div>
        </div>

        <div class="ms-panel">
          <div class="ms-panel-head">
            <span class="ms-h3">Your data</span>
          </div>
          <Row title="Export everything" desc="All reports and campaigns as JSON: your evidence, your file.">
            <button type="button" class="ms-btn ms-btn--sm" onClick={() => void send({ kind: 'exportAll' }).then((r) => download(`mailshark-export-${new Date().toISOString().slice(0, 10)}.json`, r.json))}>
              <Download /> Export
            </button>
          </Row>
          <Row title="Erase all data" desc="Permanently delete every report, campaign and sender history stored by MailShark.">
            {confirmWipe ? (
              <div class="ms-row">
                <button type="button" class="ms-btn ms-btn--sm" onClick={() => setConfirmWipe(false)}>
                  Cancel
                </button>
                <button
                  type="button"
                  class="ms-btn ms-btn--danger ms-btn--sm"
                  onClick={() =>
                    void send({ kind: 'deleteAll' }).then(() => {
                      setConfirmWipe(false);
                      ctx.refreshStats();
                    })
                  }
                >
                  <Trash2 /> Erase now
                </button>
              </div>
            ) : (
              <button type="button" class="ms-btn ms-btn--danger ms-btn--sm" onClick={() => setConfirmWipe(true)}>
                <Trash2 /> Erase…
              </button>
            )}
          </Row>
        </div>
      </div>
    </>
  );
}
