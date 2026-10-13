// Application shell: top bar (brand, breadcrumbs, case search, health, theme, account) and the
// navigation rail (case views when a case is open, platform views always).
import type { ComponentChildren } from 'preact';
import { createContext } from 'preact';
import { useContext, useEffect, useRef, useState } from 'preact/hooks';
import {
  Activity,
  BookOpen,
  Boxes,
  ChevronRight,
  FileText,
  FolderOpen,
  Gauge,
  Inbox,
  LogOut,
  Menu,
  Moon,
  Network,
  Radar,
  Search,
  Settings,
  Shield,
  Sun,
  Upload,
  User,
  Waypoints,
  Fingerprint,
} from 'lucide-preact';
import { SHARK_EYE, SHARK_PATH } from '../../../extension/brand/mark.mjs';
import { useApi } from '../lib/hooks';
import { navigate, useRoute } from '../lib/router';
import { session, signOut } from '../lib/session';
import { usePref, useStore } from '../lib/store';
import type { CaseSummary, Health } from '../lib/types';
import { Link } from './ui';

export function SharkMark({ size = 24 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 64 64" aria-hidden="true">
      <rect x="0" y="0" width="64" height="64" rx="15" fill="#0b2a44" />
      <path d="M0 50 q8 -5 16 0 t16 0 t16 0 t16 0" fill="none" stroke="#2fb5a6" stroke-opacity="0.85" stroke-width="3" stroke-linecap="round" />
      <g transform="translate(5 12) scale(0.84)">
        <path d={SHARK_PATH} fill="#e9fbfb" />
        <circle cx={SHARK_EYE.cx} cy={SHARK_EYE.cy} r={SHARK_EYE.r + 0.3} fill="#0b2a44" />
      </g>
    </svg>
  );
}

// ── Case context ──
export interface CaseCtx {
  c: CaseSummary;
  reload: () => void;
}
export const CaseContext = createContext<CaseCtx | null>(null);
export function useCase(): CaseCtx {
  const ctx = useContext(CaseContext);
  if (!ctx) throw new Error('useCase outside a case');
  return ctx;
}

// ── Theme ──
export type ThemePref = 'system' | 'dark' | 'light';
export function applyTheme(pref: ThemePref): void {
  const dark = pref === 'dark' || (pref === 'system' && window.matchMedia('(prefers-color-scheme: dark)').matches);
  document.documentElement.setAttribute('data-theme', dark ? 'dark' : 'light');
}

function ThemeToggle() {
  const [pref, setPref] = usePref<ThemePref>('theme', 'system');
  useEffect(() => applyTheme(pref), [pref]);
  const dark = document.documentElement.getAttribute('data-theme') !== 'light';
  return (
    <button class="btn btn-ghost btn-icon" title={`Theme: ${pref} (click to switch)`} aria-label="Switch colour theme" onClick={() => setPref(dark ? 'light' : 'dark')}>
      {dark ? <Sun /> : <Moon />}
    </button>
  );
}

function HealthDot() {
  const h = useApi<Health>('/api/health', undefined, { poll: 30_000 });
  const d = h.data;
  const state = h.error ? 'failed' : !d ? 'pending' : d.status === 'ok' ? 'benign' : 'suspicious';
  const title = h.error
    ? 'Server unreachable'
    : d
      ? `Server ${d.status} · platform ${d.version} · engine ${d.engine} · workers ${d.workers.busy}/${d.workers.size} busy · queue ${d.queue.queued} queued, ${d.queue.running} running · intelligence: ${d.intel.current}/${d.intel.total} sources current${d.intel.stale ? `, ${d.intel.stale} stale` : ''}${d.intel.unavailable ? `, ${d.intel.unavailable} unavailable` : ''}`
      : 'Checking server health…';
  return (
    <Link href="/intel" class="row small muted" title={title}>
      <span class="dot" data-c={state} />
      <span class="nowrap health-label">
        {d ? `${d.intel.current}/${d.intel.total} feeds current` : h.error ? 'offline' : '…'}
      </span>
    </Link>
  );
}

function UserMenu() {
  const s = useStore(session);
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const on = (e: MouseEvent): void => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener('mousedown', on);
    return () => document.removeEventListener('mousedown', on);
  }, [open]);
  if (!s.user) return null;
  return (
    <div ref={ref} style={{ position: 'relative' }}>
      <button class="btn btn-ghost" aria-haspopup="menu" aria-expanded={open} onClick={() => setOpen(!open)}>
        <User />
        <span class="trunc" style={{ maxWidth: '140px' }}>
          {s.user.displayName}
        </span>
      </button>
      {open && (
        <div class="panel" role="menu" style={{ position: 'absolute', right: 0, top: '36px', minWidth: '220px', zIndex: 50, boxShadow: 'var(--shadow)', padding: '6px' }}>
          <div class="small muted" style={{ padding: '6px 8px' }}>
            Signed in as <b class="mono">{s.user.username}</b> · {s.user.role}
          </div>
          <button class="btn btn-ghost" style={{ width: '100%', justifyContent: 'flex-start' }} role="menuitem" onClick={() => (setOpen(false), navigate('/account'))}>
            <User /> Account
          </button>
          <button
            class="btn btn-ghost"
            style={{ width: '100%', justifyContent: 'flex-start' }}
            role="menuitem"
            onClick={() => {
              setOpen(false);
              void signOut().then(() => navigate('/login'));
            }}
          >
            <LogOut /> Sign out
          </button>
        </div>
      )}
    </div>
  );
}

function CaseSearch({ caseId }: { caseId: string }) {
  const [q, setQ] = useState('');
  return (
    <form
      class="search input-icon"
      role="search"
      onSubmit={(e) => {
        e.preventDefault();
        if (q.trim()) navigate(`/cases/${caseId}/messages?q=${encodeURIComponent(q.trim())}`);
      }}
    >
      <Search />
      <input class="input" placeholder="Search subject, sender, Message-ID, SHA-256…" value={q} onInput={(e) => setQ((e.target as HTMLInputElement).value)} aria-label="Search messages in this case" />
    </form>
  );
}

interface NavItem {
  href: string;
  label: string;
  icon: ComponentChildren;
  count?: number | null;
  match?: (path: string) => boolean;
}

function NavLink({ item, path }: { item: NavItem; path: string }) {
  const active = item.match ? item.match(path) : path === item.href;
  return (
    <a
      href={item.href}
      aria-current={active ? 'page' : undefined}
      title={item.label}
      onClick={(e) => {
        if (e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey) return;
        e.preventDefault();
        navigate(item.href);
      }}
    >
      {item.icon}
      <span class="label">{item.label}</span>
      {item.count !== undefined && item.count !== null && item.count > 0 && <span class="count">{item.count.toLocaleString()}</span>}
    </a>
  );
}

export function Shell({ children, fill, caseSummary, crumbs }: { children: ComponentChildren; fill?: boolean; caseSummary?: CaseSummary | null; crumbs?: { label: string; href?: string }[] }) {
  const { path } = useRoute();
  const s = useStore(session);
  const [collapsed, setCollapsed] = usePref<boolean>('nav.collapsed', false);
  const c = caseSummary;
  const base = c ? `/cases/${c.id}` : '';
  const caseItems: NavItem[] = c
    ? [
        { href: base, label: 'Overview', icon: <Gauge /> },
        { href: `${base}/evidence`, label: 'Evidence', icon: <Upload />, count: c.counts.evidence, match: (p) => p.startsWith(`${base}/evidence`) },
        { href: `${base}/messages`, label: 'Messages', icon: <Inbox />, count: c.counts.messages, match: (p) => p.startsWith(`${base}/messages`) },
        { href: `${base}/indicators`, label: 'Indicators', icon: <Fingerprint />, match: (p) => p.startsWith(`${base}/indicators`) },
        { href: `${base}/campaigns`, label: 'Campaigns', icon: <Boxes />, count: c.counts.clusters + c.counts.externalCampaigns || null, match: (p) => p.startsWith(`${base}/campaigns`) },
        { href: `${base}/graph`, label: 'Graph', icon: <Waypoints />, match: (p) => p.startsWith(`${base}/graph`) },
        { href: `${base}/reports`, label: 'Reports', icon: <FileText />, match: (p) => p.startsWith(`${base}/reports`) },
        { href: `${base}/activity`, label: 'Activity', icon: <Activity />, match: (p) => p.startsWith(`${base}/activity`) },
        { href: `${base}/settings`, label: 'Case settings', icon: <Settings />, match: (p) => p.startsWith(`${base}/settings`) },
      ]
    : [];
  const platformItems: NavItem[] = [
    { href: '/', label: 'Cases', icon: <FolderOpen />, match: (p) => p === '/' || p === '/cases' },
    { href: '/intel', label: 'Intelligence sources', icon: <Radar />, match: (p) => p.startsWith('/intel') },
    ...(s.user?.role === 'admin' ? [{ href: '/admin', label: 'Administration', icon: <Shield />, match: (p: string) => p.startsWith('/admin') }] : []),
    { href: '/docs', label: 'Method & limits', icon: <BookOpen />, match: (p) => p.startsWith('/docs') },
  ];
  return (
    <div class="shell" data-nav={collapsed ? 'collapsed' : undefined}>
      <header class="topbar">
        <button class="btn btn-ghost btn-icon" aria-label={collapsed ? 'Expand navigation' : 'Collapse navigation'} onClick={() => setCollapsed(!collapsed)}>
          <Menu />
        </button>
        <Link href="/" class="brand">
          <SharkMark size={24} />
          <span>MailShark</span>
          <span class="sub">Forensics</span>
        </Link>
        {crumbs && crumbs.length > 0 && (
          <nav class="crumbs" aria-label="Breadcrumb">
            {crumbs.map((cr, i) => (
              <>
                <ChevronRight size={14} class="sep" />
                {cr.href && i < crumbs.length - 1 ? (
                  <Link href={cr.href} class="trunc">
                    {cr.label}
                  </Link>
                ) : (
                  <span class="trunc" style={{ color: 'var(--text)', maxWidth: '360px' }}>
                    {cr.label}
                  </span>
                )}
              </>
            ))}
          </nav>
        )}
        {c ? <CaseSearch caseId={c.id} /> : <span class="spacer" />}
        <HealthDot />
        <ThemeToggle />
        <UserMenu />
      </header>
      <nav class="nav" aria-label="Main">
        {c && (
          <>
            <div class="nav-section trunc" title={c.name}>
              Case · {c.reference || c.name}
            </div>
            {caseItems.map((i) => (
              <NavLink item={i} path={path} />
            ))}
          </>
        )}
        <div class="nav-section">Platform</div>
        {platformItems.map((i) => (
          <NavLink item={i} path={path} />
        ))}
        <div class="nav-foot small faint">
          <Network size={12} /> <span class="label">Self-hosted · data stays on this server</span>
        </div>
      </nav>
      <main class={`main${fill ? ' fill' : ''}`} id="main">
        {children}
      </main>
    </div>
  );
}
