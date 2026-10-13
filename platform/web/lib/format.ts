// Display formatting. Times are shown in UTC (marked "Z") so that analysts in different time zones
// read the same timeline; the local time is available in the tooltip.

const pad = (n: number): string => String(n).padStart(2, '0');

export function fmtTime(ms: number | null | undefined, seconds = true): string {
  if (ms === null || ms === undefined || !Number.isFinite(ms)) return '—';
  const d = new Date(ms);
  if (Number.isNaN(d.getTime())) return '—';
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}${seconds ? ':' + pad(d.getUTCSeconds()) : ''}Z`;
}

export function fmtDate(ms: number | null | undefined): string {
  if (ms === null || ms === undefined || !Number.isFinite(ms)) return '—';
  const d = new Date(ms);
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}`;
}

export function fmtLocal(ms: number | null | undefined): string {
  if (ms === null || ms === undefined || !Number.isFinite(ms)) return '';
  return new Date(ms).toLocaleString();
}

export function fmtAgo(ms: number | null | undefined, now = Date.now()): string {
  if (ms === null || ms === undefined || !Number.isFinite(ms)) return 'never';
  const s = Math.round((now - ms) / 1000);
  const future = s < 0;
  const a = Math.abs(s);
  const v = a < 45 ? 'moments' : a < 3600 ? `${Math.round(a / 60)} min` : a < 86400 ? `${Math.round(a / 3600)} h` : a < 86400 * 60 ? `${Math.round(a / 86400)} days` : a < 86400 * 730 ? `${Math.round(a / (86400 * 30))} months` : `${Math.round(a / (86400 * 365))} years`;
  if (v === 'moments') return future ? 'in a moment' : 'just now';
  return future ? `in ${v}` : `${v} ago`;
}

export function fmtDuration(sec: number | null | undefined): string {
  if (sec === null || sec === undefined || !Number.isFinite(sec)) return '—';
  const a = Math.abs(sec);
  const sign = sec < 0 ? '−' : '';
  if (a < 1) return `${sign}${Math.round(a * 1000)} ms`;
  if (a < 120) return `${sign}${Math.round(a)} s`;
  if (a < 7200) return `${sign}${Math.round(a / 60)} min`;
  if (a < 172800) return `${sign}${(a / 3600).toFixed(1)} h`;
  return `${sign}${(a / 86400).toFixed(1)} days`;
}

export function fmtBytes(n: number | null | undefined): string {
  if (n === null || n === undefined || !Number.isFinite(n)) return '—';
  if (n < 1024) return `${n} B`;
  const u = ['KB', 'MB', 'GB', 'TB'];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < u.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v < 10 ? v.toFixed(1) : Math.round(v)} ${u[i]}`;
}

export function fmtNum(n: number | null | undefined): string {
  if (n === null || n === undefined || !Number.isFinite(n)) return '—';
  return n.toLocaleString('en-US');
}

export function pct(x: number | null | undefined, digits = 0): string {
  if (x === null || x === undefined || !Number.isFinite(x)) return '—';
  return `${(x * 100).toFixed(digits)}%`;
}

export function short(s: string | null | undefined, n = 12): string {
  if (!s) return '—';
  return s.length > n ? `${s.slice(0, n)}…` : s;
}

export function plural(n: number, one: string, many = `${one}s`): string {
  return `${fmtNum(n)} ${n === 1 ? one : many}`;
}

export function cap(s: string): string {
  return s ? s[0]!.toUpperCase() + s.slice(1) : s;
}

/** Human label for kebab-case identifiers ("reported-association" → "Reported association"). */
export function human(s: string | null | undefined): string {
  if (!s) return '—';
  return cap(s.replace(/[-_]/g, ' '));
}

/** Defanged form for copying into tickets and chats where links auto-activate. */
export function defang(s: string): string {
  return s
    .replace(/^http/i, 'hxxp')
    .replace(/:\/\//, '[://]')
    .replace(/\./g, '[.]')
    .replace(/@/g, '[@]');
}
