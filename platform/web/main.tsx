// MailShark Forensic Platform: web client entry. Routes, session gate, case layout.
import { render, type JSX } from 'preact';
import { useEffect } from 'preact/hooks';
import { onUnauthenticated } from './lib/api';
import { useApi } from './lib/hooks';
import { match, navigate, useRoute } from './lib/router';
import { refreshSession, session } from './lib/session';
import { prefs, useStore } from './lib/store';
import type { CaseSummary } from './lib/types';
import { applyTheme, CaseContext, Shell, type ThemePref } from './components/Shell';
import { Empty, ErrorBox, Loading, Toasts } from './components/ui';
import { Login, Setup } from './pages/Auth';
import { CaseList } from './pages/Cases';
import { Overview } from './pages/Overview';
import { Evidence } from './pages/Evidence';
import { Messages } from './pages/Messages';
import { Indicators } from './pages/Indicators';
import { Campaigns } from './pages/Campaigns';
import { Graph } from './pages/Graph';
import { Reports } from './pages/Reports';
import { ActivityPage } from './pages/Activity';
import { CaseSettings } from './pages/CaseSettings';
import { IntelSources } from './pages/Intel';
import { Admin } from './pages/Admin';
import { Account } from './pages/Account';
import { Docs } from './pages/Docs';

applyTheme(prefs.get<ThemePref>('theme', 'system'));
window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => applyTheme(prefs.get<ThemePref>('theme', 'system')));

onUnauthenticated(() => {
  session.set({ user: null });
  if (!location.pathname.startsWith('/login')) navigate(`/login?next=${encodeURIComponent(location.pathname + location.search)}`, { replace: true });
});

const CASE_PAGES: { path: string; label: string; fill?: boolean; view: () => JSX.Element }[] = [
  { path: '', label: 'Overview', view: () => <Overview /> },
  { path: 'evidence', label: 'Evidence', view: () => <Evidence /> },
  { path: 'messages', label: 'Messages', fill: true, view: () => <Messages /> },
  { path: 'indicators', label: 'Indicators', fill: true, view: () => <Indicators /> },
  { path: 'campaigns', label: 'Campaigns', view: () => <Campaigns /> },
  { path: 'graph', label: 'Graph', fill: true, view: () => <Graph /> },
  { path: 'reports', label: 'Reports', view: () => <Reports /> },
  { path: 'activity', label: 'Activity', view: () => <ActivityPage /> },
  { path: 'settings', label: 'Settings', view: () => <CaseSettings /> },
];

function CaseLayout({ id, sub }: { id: string; sub: string }) {
  const res = useApi<CaseSummary>(`/api/cases/${id}`, undefined, { poll: 4000 });
  const page = CASE_PAGES.find((p) => p.path === sub);
  const c = res.data && res.data.id === id ? res.data : null;
  useEffect(() => {
    document.title = c ? `${page?.label ?? 'Case'} · ${c.name} · MailShark` : 'MailShark Forensics';
  }, [c?.name, page?.label]);
  if (res.error && !c)
    return (
      <Shell crumbs={[{ label: 'Cases', href: '/' }, { label: 'Not available' }]}>
        <div class="page">{res.error.status === 404 ? <Empty title="Case not found">It does not exist, or you are not a member of it.</Empty> : <ErrorBox error={res.error} retry={res.reload} />}</div>
      </Shell>
    );
  if (!c)
    return (
      <Shell>
        <Loading />
      </Shell>
    );
  return (
    <CaseContext.Provider value={{ c, reload: res.reload }}>
      <Shell caseSummary={c} fill={page?.fill} crumbs={[{ label: 'Cases', href: '/' }, { label: c.name, href: `/cases/${c.id}` }, ...(page && page.path ? [{ label: page.label }] : [])]}>
        {page ? page.view() : <div class="page"><Empty title="No such page" /></div>}
      </Shell>
    </CaseContext.Provider>
  );
}

function App() {
  const s = useStore(session);
  const { path } = useRoute();
  useEffect(() => {
    void refreshSession().catch(() => session.set({ loaded: true }));
  }, []);
  if (!s.loaded) return <Loading label="Connecting…" />;
  if (s.setupNeeded) return <Setup />;
  if (!s.user) {
    if (path !== '/login') {
      navigate(`/login?next=${encodeURIComponent(location.pathname + location.search)}`, { replace: true });
      return null;
    }
    return <Login />;
  }
  if (path === '/login') {
    navigate('/', { replace: true });
    return null;
  }
  const cm = /^\/cases\/([^/]+)(?:\/([^/]+))?\/?$/.exec(path);
  if (cm) return <CaseLayout id={decodeURIComponent(cm[1] as string)} sub={cm[2] ?? ''} />;
  const page = (title: string, body: JSX.Element, crumbs = [{ label: title }]) => {
    document.title = `${title} · MailShark`;
    return <Shell crumbs={crumbs}>{body}</Shell>;
  };
  if (path === '/' || path === '/cases') return page('Cases', <CaseList />, []);
  if (match('/intel', path)) return page('Intelligence sources', <IntelSources />);
  if (match('/admin', path)) return s.user.role === 'admin' ? page('Administration', <Admin />) : page('Administration', <div class="page"><Empty title="Administrators only" /></div>);
  if (match('/account', path)) return page('Account', <Account />);
  if (match('/docs', path)) return page('Method & limits', <Docs />);
  return page('Not found', <div class="page"><Empty title="Page not found" /></div>);
}

function Root() {
  return (
    <>
      <App />
      <Toasts />
    </>
  );
}

render(<Root />, document.getElementById('app') as HTMLElement);
