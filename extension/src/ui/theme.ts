import { useEffect, useState } from 'preact/hooks';
import { DEFAULT_SETTINGS, loadSettings, onSettingsChanged, type Settings } from '../shared/settings';

export function resolveTheme(pref: Settings['theme']): 'dark' | 'light' {
  if (pref === 'dark' || pref === 'light') return pref;
  return typeof matchMedia === 'function' && matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
}

/** Live settings for extension pages; also keeps <html data-theme> in sync. */
export function useSettings(): [Settings, boolean] {
  const [s, setS] = useState<Settings>(DEFAULT_SETTINGS);
  const [ready, setReady] = useState(false);
  useEffect(() => {
    void loadSettings().then((v) => {
      setS(v);
      setReady(true);
    });
    return onSettingsChanged(setS);
  }, []);
  useEffect(() => {
    const apply = (): void => document.documentElement.setAttribute('data-theme', resolveTheme(s.theme));
    apply();
    if (s.theme !== 'system' || typeof matchMedia !== 'function') return;
    const mq = matchMedia('(prefers-color-scheme: light)');
    mq.addEventListener('change', apply);
    return () => mq.removeEventListener('change', apply);
  }, [s.theme]);
  return [s, ready];
}
