// Outbound HTTP for intelligence sources. The only place the platform talks to the internet.
// SSRF guard: each connector declares the exact hosts it may contact; redirects are followed
// manually and must stay inside that allowlist. Nothing from evidence ever becomes a request URL
// (indicator values are only ever sent as parameters to these fixed endpoints).

export class HttpError extends Error {
  constructor(
    message: string,
    readonly status: number | null,
    readonly retryable: boolean,
  ) {
    super(message);
  }
}

export interface FetchOptions {
  allowedHosts: string[];
  method?: 'GET' | 'POST';
  headers?: Record<string, string>;
  body?: string;
  timeoutMs?: number;
  maxBytes?: number;
  etag?: string | null;
  lastModified?: string | null;
  retries?: number;
  /** Plain http is only allowed when the connector explicitly needs it. */
  allowHttp?: boolean;
}

export interface FetchResult {
  status: number;
  notModified: boolean;
  bytes: Buffer;
  etag: string | null;
  lastModified: string | null;
  contentType: string | null;
  url: string;
}

export const USER_AGENT = 'MailShark-Forensics/1.0 (+https://github.com/jyo-coded/MailShark)';

function hostAllowed(url: URL, allowed: string[]): boolean {
  const h = url.hostname.toLowerCase();
  return allowed.some((a) => h === a.toLowerCase());
}

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

async function once(urlStr: string, o: FetchOptions): Promise<FetchResult> {
  let current = urlStr;
  for (let hop = 0; hop < 5; hop++) {
    const url = new URL(current);
    if (url.protocol !== 'https:' && !(o.allowHttp && url.protocol === 'http:')) throw new HttpError(`refused non-HTTPS URL ${url.origin}`, null, false);
    if (!hostAllowed(url, o.allowedHosts)) throw new HttpError(`refused host ${url.hostname} (not in the connector allowlist)`, null, false);
    if (url.username || url.password) throw new HttpError('refused URL with credentials', null, false);
    const headers: Record<string, string> = { 'user-agent': USER_AGENT, accept: '*/*', ...(o.headers ?? {}) };
    if (o.etag) headers['if-none-match'] = o.etag;
    if (o.lastModified) headers['if-modified-since'] = o.lastModified;
    let res: Response;
    try {
      res = await fetch(url, { method: o.method ?? 'GET', headers, ...(o.body !== undefined ? { body: o.body } : {}), redirect: 'manual', signal: AbortSignal.timeout(o.timeoutMs ?? 120_000) });
    } catch (e) {
      const msg = e instanceof Error ? `${e.name}: ${e.message}${(e as { cause?: { code?: string } }).cause?.code ? ` (${(e as { cause?: { code?: string } }).cause?.code})` : ''}` : String(e);
      throw new HttpError(`network error contacting ${url.hostname}: ${msg}`, null, true);
    }
    if (res.status >= 300 && res.status < 400 && res.status !== 304) {
      const loc = res.headers.get('location');
      await res.body?.cancel();
      if (!loc) throw new HttpError(`redirect without location from ${url.hostname}`, res.status, false);
      current = new URL(loc, url).toString();
      continue;
    }
    if (res.status === 304) {
      await res.body?.cancel();
      return { status: 304, notModified: true, bytes: Buffer.alloc(0), etag: o.etag ?? null, lastModified: o.lastModified ?? null, contentType: null, url: current };
    }
    if (!res.ok) {
      const retryAfter = Number(res.headers.get('retry-after'));
      const text = (await res.text().catch(() => '')).slice(0, 200).replace(/\s+/g, ' ');
      const err = new HttpError(`HTTP ${res.status} from ${url.hostname}${text ? `: ${text}` : ''}`, res.status, res.status === 429 || res.status >= 500);
      (err as HttpError & { retryAfterMs?: number }).retryAfterMs = Number.isFinite(retryAfter) && retryAfter > 0 ? Math.min(retryAfter * 1000, 120_000) : undefined;
      throw err;
    }
    const max = o.maxBytes ?? 512 * 1024 * 1024;
    const len = Number(res.headers.get('content-length'));
    if (Number.isFinite(len) && len > max) {
      await res.body?.cancel();
      throw new HttpError(`response from ${url.hostname} is ${len} bytes, above the ${max}-byte limit`, res.status, false);
    }
    const chunks: Buffer[] = [];
    let total = 0;
    if (res.body) {
      for await (const chunk of res.body as unknown as AsyncIterable<Uint8Array>) {
        total += chunk.length;
        if (total > max) throw new HttpError(`response from ${url.hostname} exceeded ${max} bytes`, res.status, false);
        chunks.push(Buffer.from(chunk));
      }
    }
    return {
      status: res.status,
      notModified: false,
      bytes: Buffer.concat(chunks),
      etag: res.headers.get('etag'),
      lastModified: res.headers.get('last-modified'),
      contentType: res.headers.get('content-type'),
      url: current,
    };
  }
  throw new HttpError(`too many redirects for ${urlStr}`, null, false);
}

/** GET/POST with retries on network errors, 429 and 5xx (exponential backoff, honours Retry-After). */
export async function fetchResource(url: string, o: FetchOptions): Promise<FetchResult> {
  const retries = o.retries ?? 2;
  let lastErr: unknown = null;
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      return await once(url, o);
    } catch (e) {
      lastErr = e;
      if (!(e instanceof HttpError) || !e.retryable || attempt === retries) break;
      const wait = (e as HttpError & { retryAfterMs?: number }).retryAfterMs ?? 2000 * 4 ** attempt;
      await sleep(wait);
    }
  }
  throw lastErr;
}
