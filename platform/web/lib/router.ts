// History-API router. Filters and selections live in the query string, so every view is linkable
// and Back/Forward restore the exact investigative context.
import { createStore, useStore } from './store';

const routeStore = createStore({ path: location.pathname, search: location.search });

window.addEventListener('popstate', () => routeStore.set({ path: location.pathname, search: location.search }));

export function navigate(to: string, opts: { replace?: boolean } = {}): void {
  if (to === location.pathname + location.search) return;
  history[opts.replace ? 'replaceState' : 'pushState'](null, '', to);
  routeStore.set({ path: location.pathname, search: location.search });
}

export interface Route {
  path: string;
  query: URLSearchParams;
}

export function useRoute(): Route {
  const r = useStore(routeStore);
  return { path: r.path, query: new URLSearchParams(r.search) };
}

/** Matches "/cases/:id/messages" against a path; returns the parameters or null. */
export function match(pattern: string, path: string): Record<string, string> | null {
  const p = pattern.split('/').filter(Boolean);
  const s = path.split('/').filter(Boolean);
  if (p.length !== s.length) return null;
  const out: Record<string, string> = {};
  for (let i = 0; i < p.length; i++) {
    const a = p[i] as string;
    const b = s[i] as string;
    if (a.startsWith(':')) out[a.slice(1)] = decodeURIComponent(b);
    else if (a !== b) return null;
  }
  return out;
}

/** Updates query parameters on the current path (null removes a parameter). */
export function setQuery(patch: Record<string, string | number | null | undefined>, opts: { replace?: boolean } = { replace: true }): void {
  const q = new URLSearchParams(location.search);
  for (const [k, v] of Object.entries(patch)) {
    if (v === null || v === undefined || v === '') q.delete(k);
    else q.set(k, String(v));
  }
  const s = q.toString();
  navigate(location.pathname + (s ? `?${s}` : ''), opts);
}

export function href(path: string, query?: Record<string, string | number | null | undefined>): string {
  if (!query) return path;
  const q = new URLSearchParams();
  for (const [k, v] of Object.entries(query)) if (v !== null && v !== undefined && v !== '') q.set(k, String(v));
  const s = q.toString();
  return s ? `${path}?${s}` : path;
}

/** Click handler for in-app anchors: plain clicks navigate in place, modified clicks open normally. */
export function linkClick(e: MouseEvent, to: string): void {
  if (e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
  e.preventDefault();
  navigate(to);
}
