// Gmail overlay controller: watches the page, dissects opened emails, renders banners, the Dissector
// drawer, the link guard and inbox-radar badges.
import { render } from 'preact';
import { ext } from '../shared/ext';
import { DEFAULT_SETTINGS, loadSettings, onSettingsChanged, type Settings } from '../shared/settings';
import { send, type CampaignRecord, type GuardLink, type ReportSummary, type StoredReport } from '../shared/protocol';
import * as gmail from './gmail';
import { createHost, injectFonts, type Host } from './shadow';
import { Banner, type BannerState } from './Banner';
import { Guard, HoverCard } from './Guard';
import { Dissector } from '../ui/dissector/Dissector';
import { SharkMark } from '../ui/SharkMark';
import { RefreshCw } from '../ui/icons';

// ── State ───────────────────────────────────────────────────────────────────

interface MsgState {
  id: string;
  state: BannerState;
  host: Host | null;
  dismissed: boolean;
  queued: boolean;
}

type RadarEntry = { status: 'unknown' | 'queued' | 'scan' | 'done' | 'error'; summary?: ReportSummary };

const messages = new Map<string, MsgState>();
const radar = new Map<string, RadarEntry>();
const badgeHosts = new WeakMap<HTMLElement, Host>();
let settings: Settings = DEFAULT_SETTINGS;
let activeId: string | null = null;

interface OverlayState {
  drawer: { stored: StoredReport; campaign: { campaign: CampaignRecord; members: ReportSummary[] } | null } | { loading: true } | null;
  closing: boolean;
  guard: GuardLink | null;
  hover: { link: GuardLink; x: number; y: number } | null;
}
const overlay: OverlayState = { drawer: null, closing: false, guard: null, hover: null };
let overlayHost: Host | null = null;
let lastFocus: HTMLElement | null = null;

function themeFor(el?: Element | null): 'dark' | 'light' {
  if (settings.overlayTheme !== 'auto') return settings.overlayTheme;
  return gmail.backgroundLuminance(el ?? document.querySelector('div[role="main"]') ?? document.body) < 0.35 ? 'dark' : 'light';
}

// ── Analysis queue (opened emails first, radar second) ──────────────────────

type Job = { id: string; priority: 0 | 1; force: boolean; resolve: (s: ReportSummary | null) => void };
const jobs: Job[] = [];
let running = 0;
const MAX_PARALLEL = 2;
let radarBudget = 60;
setInterval(() => (radarBudget = 60), 10 * 60 * 1000);

function enqueue(id: string, priority: 0 | 1, force = false): Promise<ReportSummary | null> {
  return new Promise((resolve) => {
    jobs.push({ id, priority, force, resolve });
    jobs.sort((a, b) => a.priority - b.priority);
    pump();
  });
}

function pump(): void {
  while (running < MAX_PARALLEL && jobs.length) {
    const job = jobs.shift() as Job;
    running++;
    void runJob(job).finally(() => {
      running--;
      setTimeout(pump, job.priority === 1 ? 700 : 0);
    });
  }
}

async function runJob(job: Job): Promise<void> {
  try {
    if (!job.force) {
      const known = await send({ kind: 'summaries', messageIds: [job.id] });
      const hit = known[job.id];
      if (hit) return job.resolve(hit);
    }
    const raw = await gmail.fetchRaw(job.id);
    const res = await send({ kind: 'analyze', raw, meta: { source: 'gmail', messageId: job.id, threadId: gmail.currentThreadId(), fileName: null }, force: job.force });
    if (!res.ok) throw new Error(res.error);
    job.resolve(res.summary);
  } catch (e) {
    const ms = messages.get(job.id);
    if (ms && job.priority === 0) {
      ms.state = { status: 'error', message: e instanceof Error ? e.message : String(e) };
      renderBanner(ms);
    }
    job.resolve(null);
  }
}

async function dissect(ms: MsgState, force = false): Promise<void> {
  ms.state = { status: 'scan' };
  ms.queued = true;
  renderBanner(ms);
  const summary = await enqueue(ms.id, 0, force);
  ms.queued = false;
  if (summary) {
    ms.state = { status: 'done', summary };
    radar.set(ms.id, { status: 'done', summary });
  }
  renderBanner(ms);
  refreshRadarBadges();
}

// ── Banners ─────────────────────────────────────────────────────────────────

function renderBanner(ms: MsgState): void {
  if (!ms.host) return;
  const verdict = ms.state.status === 'done' ? ms.state.summary.verdict : ms.state.status;
  ms.host.root.setAttribute('data-verdict', verdict);
  render(
    ms.dismissed ? null : (
      <Banner
        state={ms.state}
        safeMode={settings.safeBanner}
        onDissect={() => void openDrawer(ms.id)}
        onRetry={() => void dissect(ms, true)}
        onDismiss={() => {
          ms.dismissed = true;
          renderBanner(ms);
        }}
      />
    ),
    ms.host.root,
  );
}

function mountBanner(ms: MsgState, el: HTMLElement): void {
  if (ms.host?.host.isConnected && el.contains(ms.host.host)) return;
  if (ms.host) {
    render(null, ms.host.root);
    ms.host.host.remove();
    ms.host = null;
  }
  const anchor = gmail.bannerAnchor(el);
  if (!anchor) return;
  ms.host = createHost('banner', themeFor(el));
  anchor.parent.insertBefore(ms.host.host, anchor.before);
  renderBanner(ms);
}

function teardownBanners(): void {
  for (const ms of messages.values()) {
    if (ms.host) {
      render(null, ms.host.root);
      ms.host.host.remove();
      ms.host = null;
    }
  }
}

// ── Overlay: drawer, guard, hover card ──────────────────────────────────────

function ensureOverlay(): Host {
  if (overlayHost?.host.isConnected) return overlayHost;
  overlayHost = createHost('overlay', themeFor());
  overlayHost.host.style.setProperty('position', 'relative');
  overlayHost.host.style.setProperty('z-index', '2147483000');
  document.body.appendChild(overlayHost.host);
  return overlayHost;
}

function closeDrawer(): void {
  if (!overlay.drawer) return;
  overlay.closing = true;
  renderOverlay();
  setTimeout(() => {
    overlay.drawer = null;
    overlay.closing = false;
    renderOverlay();
    lastFocus?.focus?.();
  }, 200);
}

function renderOverlay(): void {
  const host = ensureOverlay();
  host.root.setAttribute('data-theme', themeFor());
  const d = overlay.drawer;
  render(
    <>
      {d && (
        <>
          <div class="ms-drawer-scrim" onClick={closeDrawer} />
          <div class="ms-drawer" data-closing={overlay.closing ? '' : undefined} role="dialog" aria-modal="true" aria-label="MailShark Dissector">
            {'loading' in d ? (
              <div class="ms-dx" style={{ display: 'grid', placeItems: 'center' }}>
                <div class="ms-col" style={{ alignItems: 'center' }}>
                  <SharkMark size={56} state="scan" />
                  <span class="ms-muted">Opening the Dissector…</span>
                </div>
              </div>
            ) : (
              <Dissector stored={d.stored} campaign={d.campaign} onClose={closeDrawer} onOpenReport={(id) => void openReport(id)} onOpenLab={() => void send({ kind: 'openLab' })} />
            )}
          </div>
        </>
      )}
      {overlay.guard && (
        <Guard
          link={overlay.guard}
          onBack={() => {
            overlay.guard = null;
            renderOverlay();
          }}
          onProceed={() => {
            const url = overlay.guard?.url;
            overlay.guard = null;
            renderOverlay();
            if (url && /^https?:/i.test(url)) window.open(url, '_blank', 'noopener,noreferrer');
          }}
        />
      )}
      {overlay.hover && !overlay.guard && <HoverCard link={overlay.hover.link} x={overlay.hover.x} y={overlay.hover.y} />}
    </>,
    host.root,
  );
}

async function openReport(reportId: string): Promise<void> {
  const stored = await send({ kind: 'report', id: reportId });
  if (!stored) return;
  const campaign = stored.meta.clusterId ? await send({ kind: 'campaign', id: stored.meta.clusterId }) : null;
  overlay.drawer = { stored, campaign };
  renderOverlay();
}

async function openDrawer(messageId: string): Promise<void> {
  const ms = messages.get(messageId);
  if (!ms || ms.state.status !== 'done') return;
  lastFocus = document.activeElement as HTMLElement | null;
  overlay.drawer = { loading: true };
  overlay.closing = false;
  renderOverlay();
  await openReport(ms.state.summary.id);
}

window.addEventListener(
  'keydown',
  (e) => {
    if (e.key === 'Escape' && overlay.drawer && !overlay.guard) {
      e.stopPropagation();
      closeDrawer();
    }
  },
  true,
);

// ── Link guard & hover card ─────────────────────────────────────────────────

function normalizeUrl(u: string): string | null {
  try {
    const url = new URL(u, location.href);
    if (/(^|\.)google\.[a-z.]+$/.test(url.hostname) && url.pathname === '/url') {
      const q = url.searchParams.get('q') ?? url.searchParams.get('url');
      if (q) return new URL(q).href;
    }
    return url.href;
  } catch {
    return null;
  }
}

function guardLinkFor(anchor: HTMLAnchorElement): GuardLink | null {
  const msgEl = gmail.isInsideMessageBody(anchor);
  if (!msgEl) return null;
  const id = gmail.messageId(msgEl);
  const ms = id ? messages.get(id) : null;
  if (!ms || ms.state.status !== 'done') return null;
  const candidates = [anchor.getAttribute('href') ?? '', anchor.href, anchor.getAttribute('data-saferedirecturl') ?? ''].map(normalizeUrl).filter((x): x is string => !!x);
  for (const link of ms.state.summary.guardLinks) {
    const target = normalizeUrl(link.url);
    if (target && candidates.includes(target)) return link;
  }
  return null;
}

function isDangerous(link: GuardLink): boolean {
  return link.risk >= 3 || (link.risk >= 2 && link.flags.some((f) => ['text-href-mismatch', 'threat-intel', 'lookalike-homoglyph', 'lookalike-typosquat', 'ip-host', 'mixed-script', 'credentials-in-url', 'file-download'].includes(f)));
}

function onLinkClick(e: MouseEvent): void {
  if (!settings.linkGuard || (e.type === 'auxclick' && e.button !== 1)) return;
  const a = (e.target as Element | null)?.closest?.('a[href]') as HTMLAnchorElement | null;
  if (!a) return;
  const link = guardLinkFor(a);
  if (__MS_PREVIEW__) document.documentElement.setAttribute('data-mailshark-e2e-click', link ? `match:${link.risk}` : 'nomatch');
  if (!link || !isDangerous(link)) return;
  e.preventDefault();
  e.stopImmediatePropagation();
  overlay.hover = null;
  overlay.guard = link;
  renderOverlay();
}
window.addEventListener('click', onLinkClick, true);
window.addEventListener('auxclick', onLinkClick, true);

let hoverAnchor: HTMLAnchorElement | null = null;
window.addEventListener(
  'mouseover',
  (e) => {
    if (!settings.linkGuard) return;
    const a = (e.target as Element | null)?.closest?.('a[href]') as HTMLAnchorElement | null;
    if (a === hoverAnchor) return;
    hoverAnchor = a;
    const link = a ? guardLinkFor(a) : null;
    const next = link ? { link, x: e.clientX, y: e.clientY } : null;
    if (!next && !overlay.hover) return;
    overlay.hover = next;
    renderOverlay();
  },
  true,
);

// ── Inbox radar ─────────────────────────────────────────────────────────────

function Badge({ entry }: { entry: RadarEntry }) {
  if (entry.status === 'scan' || entry.status === 'queued')
    return (
      <span class="ms-rb ms-rb--scan" title="MailShark is dissecting this email">
        <RefreshCw />
      </span>
    );
  if (entry.status !== 'done' || !entry.summary) return null;
  const v = entry.summary.verdict;
  const label = v === 'danger' ? 'Phishing' : v === 'caution' ? 'Suspicious' : '';
  return (
    <span class={`ms-rb ms-v-${v}`} title={`MailShark: ${entry.summary.headline}: ${entry.summary.oneLiner}`}>
      <SharkMark size={12} state={v} badge={false} still />
      {label}
    </span>
  );
}

function refreshRadarBadges(): void {
  if (!settings.radar) return;
  for (const row of gmail.listRows()) {
    const id = gmail.rowMessageId(row);
    if (!id) continue;
    const entry = radar.get(id);
    let host = badgeHosts.get(row);
    if (!entry || entry.status === 'unknown' || entry.status === 'error' || (entry.status === 'done' && entry.summary?.verdict === 'safe' && settings.safeBanner === 'hidden')) {
      if (host) render(null, host.root);
      continue;
    }
    if (!host || !host.host.isConnected || !row.contains(host.host)) {
      const anchor = gmail.rowBadgeAnchor(row);
      if (!anchor?.parentElement) continue;
      host = createHost('badge', themeFor(row), 'span');
      anchor.parentElement.insertBefore(host.host, anchor);
      badgeHosts.set(row, host);
    }
    render(<Badge entry={entry} />, host.root);
  }
}

let radarLookupPending = false;
async function radarScan(): Promise<void> {
  const rows = gmail.listRows();
  if (!rows.length) return;
  const unknown: string[] = [];
  for (const row of rows) {
    const id = gmail.rowMessageId(row);
    if (id && !radar.has(id)) {
      radar.set(id, { status: 'unknown' });
      unknown.push(id);
    }
  }
  if (unknown.length && !radarLookupPending) {
    radarLookupPending = true;
    try {
      const known = await send({ kind: 'summaries', messageIds: unknown });
      for (const [id, summary] of Object.entries(known)) radar.set(id, { status: 'done', summary });
    } finally {
      radarLookupPending = false;
    }
  }
  if (settings.radarScan && settings.protection && !document.hidden) {
    const viewport = window.innerHeight;
    for (const row of rows) {
      if (radarBudget <= 0) break;
      const id = gmail.rowMessageId(row);
      const entry = id ? radar.get(id) : undefined;
      if (!id || entry?.status !== 'unknown') continue;
      const rect = row.getBoundingClientRect();
      if (rect.bottom < 0 || rect.top > viewport) continue;
      radarBudget--;
      radar.set(id, { status: 'queued' });
      void enqueue(id, 1).then((summary) => {
        radar.set(id, summary ? { status: 'done', summary } : { status: 'error' });
        refreshRadarBadges();
      });
    }
  }
  refreshRadarBadges();
}

function clearRadar(): void {
  for (const row of gmail.listRows()) {
    const host = badgeHosts.get(row);
    if (host) {
      render(null, host.root);
      host.host.remove();
      badgeHosts.delete(row);
    }
  }
}

// ── Page watcher ────────────────────────────────────────────────────────────

function scan(): void {
  if (settings.protection) {
    const open = gmail.openMessages();
    for (const el of open) {
      const id = gmail.messageId(el);
      if (!id) continue;
      let ms = messages.get(id);
      if (!ms) {
        ms = { id, state: { status: 'scan' }, host: null, dismissed: false, queued: false };
        messages.set(id, ms);
        mountBanner(ms, el);
        void dissect(ms);
      } else mountBanner(ms, el);
    }
    const last = open[open.length - 1];
    if (last) activeId = gmail.messageId(last);
    // Release UI for messages Gmail has removed from the page.
    for (const ms of messages.values()) {
      if (ms.host && !ms.host.host.isConnected) {
        render(null, ms.host.root);
        ms.host = null;
      }
    }
  } else teardownBanners();
  if (settings.radar) void radarScan();
  else clearRadar();
}

let timer: ReturnType<typeof setTimeout> | null = null;
function schedule(): void {
  if (timer) return;
  timer = setTimeout(() => {
    timer = null;
    scan();
  }, 250);
}

// ── Popup bridge ────────────────────────────────────────────────────────────

ext.runtime.onMessage.addListener((msg: unknown) => {
  const kind = (msg as { kind?: string } | null)?.kind;
  if (kind === 'tab:active') {
    const ms = activeId ? messages.get(activeId) : undefined;
    return Promise.resolve(ms && ms.state.status === 'done' ? ms.state.summary : null);
  }
  if (kind === 'tab:openDissector') {
    if (activeId) void openDrawer(activeId);
    return Promise.resolve(!!activeId);
  }
  return undefined;
});

// ── Boot ────────────────────────────────────────────────────────────────────

/** Test builds only: expose the boot stage to end-to-end tests (compiled out of releases). */
function stage(s: string): void {
  if (__MS_PREVIEW__) document.documentElement.setAttribute('data-mailshark-e2e', s);
}

async function boot(): Promise<void> {
  if (location.hostname !== 'mail.google.com' && !__MS_PREVIEW__) return;
  stage('start');
  settings = await loadSettings();
  stage('settings');
  injectFonts();
  onSettingsChanged((s) => {
    const themeChanged = s.overlayTheme !== settings.overlayTheme;
    settings = s;
    if (themeChanged) {
      teardownBanners();
      if (overlayHost) overlayHost.root.setAttribute('data-theme', themeFor());
    }
    for (const ms of messages.values()) renderBanner(ms);
    if (!s.radar) clearRadar();
    scan();
  });
  new MutationObserver(schedule).observe(document.body, { childList: true, subtree: true });
  document.addEventListener('visibilitychange', () => {
    if (!document.hidden) schedule();
  });
  scan();
  stage('ready');
}

boot().catch((e: unknown) => stage(`error:${e instanceof Error ? e.message : String(e)}`));
