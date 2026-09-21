// Small shared building blocks.
import type { ComponentChildren, JSX } from 'preact';
import { useEffect, useLayoutEffect, useRef, useState } from 'preact/hooks';
import type { Severity, Verdict } from '../../../engine/src/types';
import { Check, CircleCheck, Copy, Info, OctagonAlert, ShieldAlert, ShieldCheck, TriangleAlert } from './icons';

export const VERDICT_TEXT: Record<Verdict, string> = { danger: 'Likely phishing', caution: 'Be careful', safe: 'Looks safe' };

export function VerdictIcon({ verdict, size = 16 }: { verdict: Verdict; size?: number }) {
  if (verdict === 'danger') return <ShieldAlert size={size} />;
  if (verdict === 'caution') return <TriangleAlert size={size} />;
  return <ShieldCheck size={size} />;
}

export function SeverityIcon({ severity, trust, size = 16 }: { severity: Severity; trust?: boolean; size?: number }) {
  if (trust) return <CircleCheck size={size} />;
  if (severity === 'critical') return <OctagonAlert size={size} />;
  if (severity === 'high' || severity === 'medium') return <TriangleAlert size={size} />;
  return <Info size={size} />;
}

export function Chip({ tone, mono, icon, children, title }: { tone?: 'safe' | 'caution' | 'danger' | 'info' | 'accent'; mono?: boolean; icon?: ComponentChildren; children: ComponentChildren; title?: string }) {
  return (
    <span class={`ms-chip${tone ? ` ms-chip--${tone}` : ''}${mono ? ' ms-chip--mono' : ''}`} title={title}>
      {icon}
      <span class="ms-truncate">{children}</span>
    </span>
  );
}

export function Switch({ checked, onChange, label }: { checked: boolean; onChange: (v: boolean) => void; label: string }) {
  return <button type="button" class="ms-switch" role="switch" aria-checked={checked} aria-label={label} onClick={() => onChange(!checked)} />;
}

export function Segmented<T extends string>({ value, options, onChange, label }: { value: T; options: { value: T; label: string; icon?: ComponentChildren }[]; onChange: (v: T) => void; label: string }) {
  return (
    <div class="ms-seg" role="group" aria-label={label}>
      {options.map((o) => (
        <button type="button" aria-pressed={o.value === value} onClick={() => onChange(o.value)}>
          {o.icon}
          {o.label}
        </button>
      ))}
    </div>
  );
}

export interface TabDef<T extends string> {
  id: T;
  label: string;
  icon?: ComponentChildren;
  count?: number;
  tone?: 'danger' | 'caution';
}

export function Tabs<T extends string>({ tabs, value, onChange }: { tabs: TabDef<T>[]; value: T; onChange: (t: T) => void }) {
  const wrap = useRef<HTMLDivElement>(null);
  const [ink, setInk] = useState<{ x: number; w: number }>({ x: 0, w: 0 });
  // When the tabs overflow (narrow drawer), fade the clipped edge(s) so hidden tabs are discoverable.
  const [fade, setFade] = useState({ l: false, r: false });
  const measure = (): void => {
    const w = wrap.current;
    if (!w) return;
    const l = w.scrollLeft > 2;
    const r = w.scrollLeft + w.clientWidth < w.scrollWidth - 2;
    setFade((f) => (f.l === l && f.r === r ? f : { l, r }));
  };
  useLayoutEffect(() => {
    const el = wrap.current?.querySelector<HTMLElement>(`[data-tab="${value}"]`);
    if (el) {
      setInk({ x: el.offsetLeft + 8, w: Math.max(0, el.offsetWidth - 16) });
      el.scrollIntoView({ block: 'nearest', inline: 'nearest' });
    }
    measure();
  }, [value, tabs.length]);
  useEffect(() => {
    const w = wrap.current;
    if (!w || typeof ResizeObserver === 'undefined') return;
    const ro = new ResizeObserver(measure);
    ro.observe(w);
    return () => ro.disconnect();
  }, []);
  // A vertical mouse wheel scrolls the tab strip sideways when it overflows.
  const onWheel = (e: JSX.TargetedWheelEvent<HTMLDivElement>): void => {
    const w = e.currentTarget;
    if (w.scrollWidth <= w.clientWidth || Math.abs(e.deltaY) <= Math.abs(e.deltaX)) return;
    e.preventDefault();
    w.scrollLeft += e.deltaY * (e.deltaMode === 1 ? 16 : 1);
  };
  const onKey = (e: JSX.TargetedKeyboardEvent<HTMLDivElement>): void => {
    const i = tabs.findIndex((t) => t.id === value);
    if (e.key === 'ArrowRight' || e.key === 'ArrowLeft') {
      e.preventDefault();
      const next = tabs[(i + (e.key === 'ArrowRight' ? 1 : tabs.length - 1)) % tabs.length];
      if (next) onChange(next.id);
    }
  };
  return (
    <div class="ms-tabs" role="tablist" ref={wrap} onKeyDown={onKey} onScroll={measure} onWheel={onWheel} data-fade-l={fade.l ? '' : undefined} data-fade-r={fade.r ? '' : undefined}>
      {tabs.map((t) => (
        <button type="button" class="ms-tab" role="tab" data-tab={t.id} aria-selected={t.id === value} tabIndex={t.id === value ? 0 : -1} onClick={() => onChange(t.id)}>
          {t.icon}
          {t.label}
          {t.count !== undefined && t.count > 0 && (
            <span class="ms-tab-count" data-tone={t.tone}>
              {t.count}
            </span>
          )}
        </button>
      ))}
      <span class="ms-tab-ink" style={{ width: `${ink.w}px`, transform: `translateX(${ink.x}px)` }} />
    </div>
  );
}

export function CopyButton({ value, label = 'Copy' }: { value: string; label?: string }) {
  const [done, setDone] = useState(false);
  useEffect(() => {
    if (!done) return;
    const t = setTimeout(() => setDone(false), 1400);
    return () => clearTimeout(t);
  }, [done]);
  return (
    <button
      type="button"
      class="ms-btn ms-btn--ghost ms-btn--sm ms-btn--icon"
      aria-label={label}
      data-tip={done ? 'Copied' : label}
      onClick={(e) => {
        e.stopPropagation();
        void navigator.clipboard.writeText(value).then(() => setDone(true));
      }}
    >
      {done ? <Check /> : <Copy />}
    </button>
  );
}

export function Empty({ icon, title, children }: { icon?: ComponentChildren; title: string; children?: ComponentChildren }) {
  return (
    <div class="ms-empty">
      {icon}
      <div class="ms-h3">{title}</div>
      {children && <div style={{ maxWidth: '420px' }}>{children}</div>}
    </div>
  );
}

/** Save text as a file via a temporary object URL. */
export function download(filename: string, text: string, type = 'application/json'): void {
  const blob = new Blob([text], { type });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.rel = 'noopener';
  a.style.display = 'none';
  (document.body ?? document.documentElement).appendChild(a);
  a.click();
  setTimeout(() => {
    URL.revokeObjectURL(url);
    a.remove();
  }, 1000);
}
