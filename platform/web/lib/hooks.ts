// Data and interaction hooks.
import { useCallback, useEffect, useRef, useState } from 'preact/hooks';
import { api, ApiError, qs, type Query } from './api';
import { prefs } from './store';

export interface Resource<T> {
  data: T | null;
  error: ApiError | null;
  loading: boolean;
  reload: () => void;
}

/**
 * GET a resource; refetches when the path or query changes. Previous data stays visible while the
 * next request runs (lists do not flash). With `poll`, refreshes on an interval while the tab is visible.
 */
export function useApi<T>(path: string | null, query?: Query, opts: { poll?: number | false; keep?: boolean } = {}): Resource<T> {
  const key = path ? path + qs(query) : null;
  const [state, setState] = useState<{ key: string | null; data: T | null; error: ApiError | null; loading: boolean }>({ key: null, data: null, error: null, loading: !!key });
  const [tick, setTick] = useState(0);
  const reload = useCallback(() => setTick((t) => t + 1), []);
  useEffect(() => {
    if (!key) {
      setState({ key: null, data: null, error: null, loading: false });
      return;
    }
    const ac = new AbortController();
    setState((s) => ({ ...s, loading: true, ...(s.key !== key ? { error: null } : {}) }));
    api
      .get<T>(key, undefined, ac.signal)
      .then((data) => {
        if (!ac.signal.aborted) setState({ key, data, error: null, loading: false });
      })
      .catch((e: unknown) => {
        if (ac.signal.aborted || (e as Error).name === 'AbortError') return;
        setState((s) => ({ key, data: s.key === key ? s.data : null, error: e instanceof ApiError ? e : new ApiError(0, 'client', String(e)), loading: false }));
      });
    return () => ac.abort();
  }, [key, tick]);
  useEffect(() => {
    if (!opts.poll || !key) return;
    const t = setInterval(() => {
      if (document.visibilityState === 'visible') setTick((n) => n + 1);
    }, opts.poll);
    return () => clearInterval(t);
  }, [opts.poll, key]);
  const fresh = state.key === key;
  const keep = opts.keep ?? true;
  return { data: fresh || (keep && state.key !== null) ? state.data : null, error: fresh ? state.error : null, loading: state.loading || !fresh, reload };
}

export function useDebounced<T>(value: T, ms = 250): T {
  const [v, setV] = useState(value);
  useEffect(() => {
    const t = setTimeout(() => setV(value), ms);
    return () => clearTimeout(t);
  }, [value, ms]);
  return v;
}

/**
 * Drag handle for split panes. Writes the size (as a percentage) to a CSS variable on the container
 * and remembers it per layout.
 */
export function useSplitter(name: string, axis: 'x' | 'y', fallback: number, min = 15, max = 85): { ref: (el: HTMLElement | null) => void; onPointerDown: (e: PointerEvent) => void; value: number } {
  const [value, setValue] = useState(() => prefs.get(`split.${name}`, fallback));
  const el = useRef<HTMLElement | null>(null);
  const cssVar = axis === 'y' ? '--split-top' : '--split-left';
  const apply = (v: number): void => {
    el.current?.style.setProperty(cssVar, `${v}%`);
  };
  const ref = useCallback(
    (node: HTMLElement | null) => {
      el.current = node;
      if (node) node.style.setProperty(cssVar, `${value}%`);
    },
    [cssVar, value],
  );
  const onPointerDown = (e: PointerEvent): void => {
    const container = el.current;
    const handle = e.currentTarget as HTMLElement;
    if (!container) return;
    e.preventDefault();
    handle.setPointerCapture(e.pointerId);
    handle.setAttribute('data-drag', '');
    const rect = container.getBoundingClientRect();
    let last = value;
    const move = (ev: PointerEvent): void => {
      const ratio = axis === 'y' ? (ev.clientY - rect.top) / rect.height : (ev.clientX - rect.left) / rect.width;
      last = Math.min(max, Math.max(min, ratio * 100));
      apply(last);
    };
    const up = (): void => {
      handle.removeAttribute('data-drag');
      handle.removeEventListener('pointermove', move);
      handle.removeEventListener('pointerup', up);
      handle.removeEventListener('pointercancel', up);
      prefs.set(`split.${name}`, last);
      setValue(last);
    };
    handle.addEventListener('pointermove', move);
    handle.addEventListener('pointerup', up);
    handle.addEventListener('pointercancel', up);
  };
  return { ref, onPointerDown, value };
}

export function useMediaQuery(q: string): boolean {
  const [m, setM] = useState(() => window.matchMedia(q).matches);
  useEffect(() => {
    const mq = window.matchMedia(q);
    const on = (): void => setM(mq.matches);
    mq.addEventListener('change', on);
    return () => mq.removeEventListener('change', on);
  }, [q]);
  return m;
}

export function useKey(handler: (e: KeyboardEvent) => void, deps: unknown[]): void {
  useEffect(() => {
    const on = (e: KeyboardEvent): void => {
      const t = e.target as HTMLElement | null;
      if (t && (t.tagName === 'INPUT' || t.tagName === 'TEXTAREA' || t.tagName === 'SELECT' || t.isContentEditable)) return;
      handler(e);
    };
    window.addEventListener('keydown', on);
    return () => window.removeEventListener('keydown', on);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);
}
