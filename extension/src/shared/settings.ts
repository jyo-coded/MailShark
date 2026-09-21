import { ext } from './ext';

export type Sensitivity = 'relaxed' | 'balanced' | 'strict';
export type ThemePref = 'system' | 'dark' | 'light';

export interface Settings {
  /** Automatically dissect every email opened in Gmail. */
  protection: boolean;
  /** How to present emails that look safe. */
  safeBanner: 'full' | 'compact' | 'hidden';
  /** Show verdict badges next to emails in the inbox list. */
  radar: boolean;
  /** Proactively scan unopened emails visible in the inbox list. */
  radarScan: boolean;
  /** Intercept clicks on dangerous links. */
  linkGuard: boolean;
  /** Download public threat-intelligence feeds (no user data is sent). */
  feeds: boolean;
  sensitivity: Sensitivity;
  theme: ThemePref;
  /** Overlay theme inside Gmail; auto follows Gmail's own theme. */
  overlayTheme: 'auto' | 'dark' | 'light';
}

export const DEFAULT_SETTINGS: Settings = {
  protection: true,
  safeBanner: 'compact',
  radar: true,
  radarScan: true,
  linkGuard: true,
  feeds: true,
  sensitivity: 'balanced',
  theme: 'system',
  overlayTheme: 'auto',
};

const KEY = 'settings';

export async function loadSettings(): Promise<Settings> {
  try {
    const got = (await ext.storage.local.get(KEY)) as Record<string, Partial<Settings> | undefined>;
    return { ...DEFAULT_SETTINGS, ...(got[KEY] ?? {}) };
  } catch {
    return { ...DEFAULT_SETTINGS };
  }
}

export async function saveSettings(patch: Partial<Settings>): Promise<Settings> {
  const next = { ...(await loadSettings()), ...patch };
  await ext.storage.local.set({ [KEY]: next });
  return next;
}

export function onSettingsChanged(cb: (s: Settings) => void): () => void {
  const listener = (changes: Record<string, browser.storage.StorageChange>, area: string): void => {
    if (area !== 'local' || !changes[KEY]) return;
    cb({ ...DEFAULT_SETTINGS, ...((changes[KEY].newValue as Partial<Settings>) ?? {}) });
  };
  ext.storage.onChanged.addListener(listener);
  return () => ext.storage.onChanged.removeListener(listener);
}

/** Verdict thresholds per sensitivity (score is 0–100 risk). */
export function thresholds(s: Sensitivity): { danger: number; caution: number } {
  if (s === 'strict') return { danger: 60, caution: 25 };
  if (s === 'relaxed') return { danger: 80, caution: 45 };
  return { danger: 70, caution: 35 };
}
