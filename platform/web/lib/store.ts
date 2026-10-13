// Minimal observable stores (session, route, toasts) with a Preact hook.
import { useEffect, useState } from 'preact/hooks';

export interface Store<T> {
  get: () => T;
  set: (patch: Partial<T> | ((s: T) => Partial<T>)) => void;
  subscribe: (fn: () => void) => () => void;
}

export function createStore<T extends object>(initial: T): Store<T> {
  let state = initial;
  const listeners = new Set<() => void>();
  return {
    get: () => state,
    set: (patch) => {
      state = { ...state, ...(typeof patch === 'function' ? patch(state) : patch) };
      for (const l of [...listeners]) l();
    },
    subscribe: (fn) => {
      listeners.add(fn);
      return () => listeners.delete(fn);
    },
  };
}

export function useStore<T extends object>(store: Store<T>): T {
  const [, force] = useState(0);
  useEffect(() => store.subscribe(() => force((n) => n + 1)), [store]);
  return store.get();
}

/** localStorage wrapper that never throws (private windows, blocked storage). */
export const prefs = {
  get<T>(key: string, fallback: T): T {
    try {
      const v = localStorage.getItem(`ms.${key}`);
      return v === null ? fallback : (JSON.parse(v) as T);
    } catch {
      return fallback;
    }
  },
  set(key: string, value: unknown): void {
    try {
      localStorage.setItem(`ms.${key}`, JSON.stringify(value));
    } catch {
      /* storage unavailable: preference lasts for this page only */
    }
  },
};

export function usePref<T>(key: string, fallback: T): [T, (v: T) => void] {
  const [v, setV] = useState<T>(() => prefs.get(key, fallback));
  return [
    v,
    (next: T) => {
      prefs.set(key, next);
      setV(next);
    },
  ];
}

// ── Toasts ──
export interface Toast {
  id: number;
  kind: 'info' | 'error' | 'success';
  text: string;
}
export const toasts = createStore<{ items: Toast[] }>({ items: [] });
let toastSeq = 0;

export function toast(text: string, kind: Toast['kind'] = 'info', ms = 4500): void {
  const id = ++toastSeq;
  toasts.set((s) => ({ items: [...s.items.slice(-4), { id, kind, text }] }));
  setTimeout(() => toasts.set((s) => ({ items: s.items.filter((t) => t.id !== id) })), kind === 'error' ? ms * 2 : ms);
}

export function toastError(e: unknown): void {
  toast(e instanceof Error ? e.message : String(e), 'error');
}
