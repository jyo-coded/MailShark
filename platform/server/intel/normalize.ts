// Indicator normalisation shared by intelligence ingestion, matching and correlation, so that an
// indicator from a feed and the same indicator from an email compare equal after normalisation.
import { hostInfo, isIPv4, isIPv6 } from '../../../engine/src/util/domain';

export type IntelType = 'url' | 'domain' | 'ip' | 'md5' | 'sha1' | 'sha256' | 'email' | 'phone' | 'btc' | 'subject' | 'filename';

/** Canonical URL: lowercase scheme/host, no default port, no fragment, "/" path collapsed. */
export function canonicalUrl(raw: string): string | null {
  let s = raw.trim();
  if (!s) return null;
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) s = 'http://' + s;
  let u: URL;
  try {
    u = new URL(s);
  } catch {
    return null;
  }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
  const host = u.hostname.toLowerCase().replace(/\.$/, '');
  if (!host) return null;
  const port = u.port && !((u.protocol === 'http:' && u.port === '80') || (u.protocol === 'https:' && u.port === '443')) ? `:${u.port}` : '';
  const path = u.pathname === '/' && !u.search ? '' : u.pathname;
  return `${u.protocol}//${host}${port}${path}${u.search}`;
}

/** The same URL without its query string (feeds often list the bare landing page). */
export function urlWithoutQuery(canonical: string): string {
  const q = canonical.indexOf('?');
  const base = q >= 0 ? canonical.slice(0, q) : canonical;
  return base.replace(/\/$/, '');
}

export function hostOfUrl(canonical: string): string | null {
  try {
    return new URL(canonical).hostname.toLowerCase();
  } catch {
    return null;
  }
}

export function normHost(h: string): string | null {
  const v = h.trim().toLowerCase().replace(/\.$/, '').replace(/^\[|\]$/g, '');
  if (!v || v.length > 253) return null;
  if (isIPv4(v) || isIPv6(v)) return null;
  if (!/^[a-z0-9_*]([a-z0-9_.-]*[a-z0-9])?$/.test(v) || !v.includes('.')) return null;
  return v.replace(/^\*\./, '');
}

export function normIp(ip: string): string | null {
  const v = ip.trim().replace(/^\[|\]$/g, '').toLowerCase();
  if (isIPv4(v)) return v.split('.').map((o) => String(Number(o))).join('.');
  if (isIPv6(v)) return v;
  return null;
}

export function normEmail(e: string): string | null {
  const v = e.trim().toLowerCase().replace(/^mailto:/, '');
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v) ? v : null;
}

export function normHash(type: 'md5' | 'sha1' | 'sha256', h: string): string | null {
  const v = h.trim().toLowerCase();
  const len = type === 'md5' ? 32 : type === 'sha1' ? 40 : 64;
  return new RegExp(`^[0-9a-f]{${len}}$`).test(v) ? v : null;
}

export function normPhone(p: string): string | null {
  const plus = p.trim().startsWith('+');
  const digits = p.replace(/\D/g, '');
  if (digits.length < 7 || digits.length > 15) return null;
  return (plus ? '+' : '') + digits;
}

export function ipv4ToInt(ip: string): number | null {
  if (!isIPv4(ip)) return null;
  return ip.split('.').reduce((n, o) => n * 256 + Number(o), 0);
}

/** Candidate host names to test against host-level lists: the host, then parents down to the registrable domain. */
export function hostCandidates(host: string): string[] {
  const h = host.toLowerCase().replace(/^www\./, '');
  const reg = hostInfo(h).regDomain;
  const out = [h];
  if (!reg) return out;
  const labels = h.split('.');
  for (let i = 1; i < labels.length; i++) {
    const cand = labels.slice(i).join('.');
    if (cand.length < reg.length) break;
    out.push(cand);
  }
  return [...new Set(out)];
}

export function registrable(host: string): string | null {
  return hostInfo(host).regDomain;
}
