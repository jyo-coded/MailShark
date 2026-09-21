export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(n < 10240 ? 1 : 0)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

export function relativeTime(ts: number | string | null | undefined, now = Date.now()): string {
  if (ts === null || ts === undefined) return '—';
  const t = typeof ts === 'string' ? Date.parse(ts) : ts;
  if (!Number.isFinite(t)) return '—';
  const s = Math.round((now - t) / 1000);
  if (s < 45) return 'just now';
  if (s < 90) return '1 min ago';
  const m = Math.round(s / 60);
  if (m < 60) return `${m} min ago`;
  const h = Math.round(m / 60);
  if (h < 24) return `${h} h ago`;
  const d = Math.round(h / 24);
  if (d < 7) return `${d} d ago`;
  return new Date(t).toLocaleDateString(undefined, { day: 'numeric', month: 'short', year: d > 300 ? 'numeric' : undefined });
}

export function formatDateTime(ts: number | string | null | undefined): string {
  if (ts === null || ts === undefined) return '—';
  const t = typeof ts === 'string' ? Date.parse(ts) : ts;
  if (!Number.isFinite(t)) return '—';
  return new Date(t).toLocaleString(undefined, { day: 'numeric', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' });
}

export function formatDuration(sec: number | null): string {
  if (sec === null) return '—';
  const a = Math.abs(sec);
  if (a < 60) return `${a}s`;
  if (a < 3600) return `${Math.round(a / 60)} min`;
  if (a < 86400) return `${(a / 3600).toFixed(1)} h`;
  return `${Math.round(a / 86400)} d`;
}

export function initials(name: string, fallback: string): string {
  const src = (name || fallback || '?').replace(/[^\p{L}\p{N}\s]/gu, ' ').trim();
  const parts = src.split(/\s+/).filter(Boolean);
  if (!parts.length) return '?';
  return ((parts[0]?.[0] ?? '') + (parts.length > 1 ? (parts[parts.length - 1]?.[0] ?? '') : '')).toUpperCase();
}

export function plural(n: number, one: string, many = one + 's'): string {
  return `${n.toLocaleString()} ${n === 1 ? one : many}`;
}

export function defang(url: string): string {
  return url.replace(/^http/i, 'hxxp').replace(/\./g, '[.]');
}
