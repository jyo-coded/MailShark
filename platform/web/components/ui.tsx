// Shared UI primitives. Untrusted strings are only ever rendered as text (Preact escapes them);
// nothing in the client injects HTML.
import type { ComponentChildren, JSX } from 'preact';
import { useEffect, useRef, useState } from 'preact/hooks';
import { ChevronLeft, ChevronRight, Copy as CopyIcon, Check, Inbox, Info, TriangleAlert, OctagonAlert, X, RefreshCw } from 'lucide-preact';
import { toast, toasts, useStore } from '../lib/store';
import { fmtAgo, fmtLocal, fmtTime, human } from '../lib/format';
import { linkClick } from '../lib/router';
import type { ApiError } from '../lib/api';

export const CLASS_LABEL: Record<string, string> = { malicious: 'Malicious', suspicious: 'Suspicious', inconclusive: 'Inconclusive', benign: 'Benign', failed: 'Failed' };

export function Link({ href, children, class: cls, title }: { href: string; children: ComponentChildren; class?: string; title?: string }) {
  return (
    <a href={href} class={cls} title={title} onClick={(e) => linkClick(e as unknown as MouseEvent, href)}>
      {children}
    </a>
  );
}

export function Badge({ c, children, title, outline }: { c?: string | null; children: ComponentChildren; title?: string; outline?: boolean }) {
  return (
    <span class={`badge${outline ? ' outline' : ''}`} data-c={c ?? undefined} title={title}>
      {children}
    </span>
  );
}

export function ClassBadge({ c, title }: { c: string | null | undefined; title?: string }) {
  if (!c) return <Badge c="pending">Pending</Badge>;
  return (
    <Badge c={c} title={title}>
      {CLASS_LABEL[c] ?? human(c)}
    </Badge>
  );
}

export function ClassDot({ c }: { c: string | null | undefined }) {
  return <span class="dot" data-c={c ?? 'pending'} />;
}

export function Sev({ s }: { s: string | null | undefined }) {
  if (!s) return <span class="faint">—</span>;
  return (
    <span class="sev" data-s={s}>
      {s === 'none' ? 'none' : s}
    </span>
  );
}

export function Time({ ms, seconds = true, ago = false }: { ms: number | null | undefined; seconds?: boolean; ago?: boolean }) {
  if (ms === null || ms === undefined) return <span class="faint">—</span>;
  return (
    <time class="mono nowrap" dateTime={new Date(ms).toISOString()} title={`${fmtLocal(ms)} (local) · ${fmtAgo(ms)}`}>
      {ago ? fmtAgo(ms) : fmtTime(ms, seconds)}
    </time>
  );
}

export function CopyButton({ value, label = 'Copy' }: { value: string; label?: string }) {
  const [done, setDone] = useState(false);
  return (
    <button
      type="button"
      class="copy"
      title={label}
      aria-label={label}
      onClick={(e) => {
        e.stopPropagation();
        void navigator.clipboard
          .writeText(value)
          .then(() => {
            setDone(true);
            setTimeout(() => setDone(false), 1200);
          })
          .catch(() => toast('The clipboard is not available in this browser context.', 'error'));
      }}
    >
      {done ? <Check /> : <CopyIcon />}
    </button>
  );
}

/** Monospace value with a copy button (hashes, addresses, URLs). Never rendered as a link. */
export function Mono({ value, max, copy = true, title }: { value: string | null | undefined; max?: number; copy?: boolean; title?: string }) {
  if (!value) return <span class="faint">—</span>;
  const shown = max && value.length > max ? `${value.slice(0, max)}…` : value;
  return (
    <span class="row" style={{ gap: '4px', display: 'inline-flex', minWidth: 0, maxWidth: '100%' }}>
      <span class="mono break" title={title ?? value}>
        {shown}
      </span>
      {copy && <CopyButton value={value} />}
    </span>
  );
}

export function Spinner({ label }: { label?: string }) {
  return <span class="spinner" role="status" aria-label={label ?? 'Loading'} />;
}

export function Loading({ label = 'Loading…' }: { label?: string }) {
  return (
    <div class="empty">
      <Spinner />
      <div class="small muted" style={{ marginTop: '8px' }}>
        {label}
      </div>
    </div>
  );
}

export function Empty({ icon, title, children }: { icon?: ComponentChildren; title: string; children?: ComponentChildren }) {
  return (
    <div class="empty">
      {icon ?? <Inbox />}
      <h3>{title}</h3>
      {children && <div class="small">{children}</div>}
    </div>
  );
}

export function Notice({ c = 'info', children, icon }: { c?: 'info' | 'warn' | 'danger'; children: ComponentChildren; icon?: ComponentChildren }) {
  return (
    <div class="notice" data-c={c} role={c === 'danger' ? 'alert' : undefined}>
      {icon ?? (c === 'danger' ? <OctagonAlert /> : c === 'warn' ? <TriangleAlert /> : <Info />)}
      <div>{children}</div>
    </div>
  );
}

export function ErrorBox({ error, retry }: { error: ApiError | Error | null; retry?: () => void }) {
  if (!error) return null;
  return (
    <div style={{ padding: '16px' }}>
      <Notice c="danger">
        <div class="row wrap" style={{ justifyContent: 'space-between' }}>
          <span>{error.message}</span>
          {retry && (
            <button class="btn btn-sm" onClick={retry}>
              <RefreshCw /> Retry
            </button>
          )}
        </div>
      </Notice>
    </div>
  );
}

export function Panel({ title, actions, children, tight, class: cls, icon }: { title?: ComponentChildren; actions?: ComponentChildren; children: ComponentChildren; tight?: boolean; class?: string; icon?: ComponentChildren }) {
  return (
    <section class={`panel${cls ? ' ' + cls : ''}`}>
      {(title || actions) && (
        <div class="panel-head">
          {icon}
          {typeof title === 'string' ? <h2>{title}</h2> : title}
          {actions && <div class="actions">{actions}</div>}
        </div>
      )}
      <div class={`panel-body${tight ? ' tight' : ''}`}>{children}</div>
    </section>
  );
}

export function Kpi({ label, value, sub, c, href }: { label: string; value: ComponentChildren; sub?: ComponentChildren; c?: string; href?: string }) {
  const body = (
    <>
      <span class="k-label">{label}</span>
      <span class="k-value" data-c={c}>
        {value}
      </span>
      {sub !== undefined && <span class="k-sub">{sub}</span>}
    </>
  );
  return href ? (
    <Link class="kpi" href={href}>
      {body}
    </Link>
  ) : (
    <div class="kpi">{body}</div>
  );
}

export function DistBar({ parts, title }: { parts: { c: string; n: number }[]; title?: string }) {
  const total = parts.reduce((s, p) => s + p.n, 0);
  return (
    <div class="bar" title={title} role="img" aria-label={title ?? parts.map((p) => `${p.c} ${p.n}`).join(', ')}>
      {total > 0 && parts.filter((p) => p.n > 0).map((p) => <span data-c={p.c} style={{ width: `${(p.n / total) * 100}%` }} />)}
    </div>
  );
}

export function Field({ label, hint, children, id }: { label: string; hint?: ComponentChildren; children: ComponentChildren; id?: string }) {
  return (
    <div class="field">
      <label for={id}>{label}</label>
      {children}
      {hint && <span class="hint">{hint}</span>}
    </div>
  );
}

function useEscape(onClose: () => void): void {
  useEffect(() => {
    const on = (e: KeyboardEvent): void => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', on);
    return () => window.removeEventListener('keydown', on);
  }, [onClose]);
}

export function Dialog({ title, onClose, children, footer, wide }: { title: string; onClose: () => void; children: ComponentChildren; footer?: ComponentChildren; wide?: boolean }) {
  useEscape(onClose);
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const first = ref.current?.querySelector<HTMLElement>('input, select, textarea, button:not(.btn-icon)');
    first?.focus();
  }, []);
  return (
    <div class="dialog-scrim" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div class="dialog" role="dialog" aria-modal="true" aria-label={title} ref={ref} style={wide ? { width: 'min(760px, 100%)' } : undefined}>
        <div class="panel-head">
          <h2>{title}</h2>
          <div class="actions">
            <button class="btn btn-ghost btn-icon btn-sm" aria-label="Close" onClick={onClose}>
              <X />
            </button>
          </div>
        </div>
        <div class="panel-body">{children}</div>
        {footer && <div class="dialog-foot">{footer}</div>}
      </div>
    </div>
  );
}

export function Drawer({ title, sub, onClose, children, actions }: { title: ComponentChildren; sub?: ComponentChildren; onClose: () => void; children: ComponentChildren; actions?: ComponentChildren }) {
  useEscape(onClose);
  return (
    <div class="drawer-scrim" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <aside class="drawer" role="dialog" aria-modal="true">
        <div class="panel-head">
          <div class="grow">
            <div class="trunc" style={{ fontWeight: 600 }}>
              {title}
            </div>
            {sub && <div class="small muted trunc">{sub}</div>}
          </div>
          <div class="actions">
            {actions}
            <button class="btn btn-ghost btn-icon btn-sm" aria-label="Close" onClick={onClose}>
              <X />
            </button>
          </div>
        </div>
        <div class="drawer-body">{children}</div>
      </aside>
    </div>
  );
}

export function Tabs<T extends string>({ tabs, value, onChange }: { tabs: { id: T; label: ComponentChildren; count?: number | null; hidden?: boolean }[]; value: T; onChange: (id: T) => void }) {
  return (
    <div class="tabs" role="tablist">
      {tabs
        .filter((t) => !t.hidden)
        .map((t) => (
          <button class="tab" role="tab" aria-selected={value === t.id} onClick={() => onChange(t.id)}>
            {t.label}
            {t.count !== undefined && t.count !== null && <span class="n">{t.count}</span>}
          </button>
        ))}
    </div>
  );
}

export function Toasts() {
  const { items } = useStore(toasts);
  return (
    <div class="toasts" aria-live="polite">
      {items.map((t) => (
        <div class="toast" data-c={t.kind} key={t.id}>
          <span class="row" style={{ color: t.kind === 'error' ? 'var(--malicious)' : t.kind === 'success' ? 'var(--benign)' : 'var(--accent)', flex: 'none' }}>
            {t.kind === 'error' ? <OctagonAlert size={16} /> : t.kind === 'success' ? <Check size={16} /> : <Info size={16} />}
          </span>
          <span class="break">{t.text}</span>
        </div>
      ))}
    </div>
  );
}

export function SortTh({ col, sort, order, onSort, children, num, class: cls, style }: { col: string; sort: string; order: 'asc' | 'desc'; onSort: (col: string) => void; children: ComponentChildren; num?: boolean; class?: string; style?: JSX.CSSProperties }) {
  const active = sort === col;
  return (
    <th class={`sortable${num ? ' num' : ''}${cls ? ' ' + cls : ''}`} style={style} aria-sort={active ? (order === 'asc' ? 'ascending' : 'descending') : undefined} onClick={() => onSort(col)}>
      {children}
      {active && <span class="arrow">{order === 'asc' ? '▲' : '▼'}</span>}
    </th>
  );
}

export function Pager({ page, pageSize, total, onPage }: { page: number; pageSize: number; total: number; onPage: (p: number) => void }) {
  const pages = Math.max(1, Math.ceil(total / pageSize));
  const from = total === 0 ? 0 : page * pageSize + 1;
  const to = Math.min(total, (page + 1) * pageSize);
  return (
    <div class="pager">
      <span>
        {from.toLocaleString()}–{to.toLocaleString()} of {total.toLocaleString()}
      </span>
      <span class="spacer" />
      <button class="btn btn-sm btn-icon" disabled={page <= 0} aria-label="Previous page" onClick={() => onPage(page - 1)}>
        <ChevronLeft />
      </button>
      <span class="mono xs">
        {page + 1} / {pages}
      </span>
      <button class="btn btn-sm btn-icon" disabled={page >= pages - 1} aria-label="Next page" onClick={() => onPage(page + 1)}>
        <ChevronRight />
      </button>
    </div>
  );
}

export function KV({ rows }: { rows: [ComponentChildren, ComponentChildren][] }) {
  return (
    <dl class="kv">
      {rows.map(([k, v]) => (
        <>
          <dt>{k}</dt>
          <dd>{v ?? <span class="faint">—</span>}</dd>
        </>
      ))}
    </dl>
  );
}

/**
 * External reference from an intelligence record. Feed content is untrusted: only https links to the
 * source's own published hosts are rendered as links; anything else is shown as copyable text.
 */
const REFERENCE_HOSTS = ['urlhaus.abuse.ch', 'threatfox.abuse.ch', 'bazaar.abuse.ch', 'feodotracker.abuse.ch', 'otx.alienvault.com', 'www.virustotal.com', 'phishtank.org', 'www.phishtank.com', 'openphish.com', 'www.circl.lu', 'www.botvrij.eu', 'attack.mitre.org', 'github.com'];

export function SafeRef({ url }: { url: string | null | undefined }) {
  if (!url) return <span class="faint">—</span>;
  let ok = false;
  try {
    const u = new URL(url);
    ok = u.protocol === 'https:' && REFERENCE_HOSTS.includes(u.hostname);
  } catch {
    ok = false;
  }
  if (!ok) return <Mono value={url} max={80} />;
  return (
    <a href={url} target="_blank" rel="noopener noreferrer nofollow" class="mono small break">
      {url}
    </a>
  );
}
