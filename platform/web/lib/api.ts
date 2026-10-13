// Thin client for the platform API: JSON in and out, the CSRF header on every mutation, typed errors.
// Uploads use XMLHttpRequest because fetch() cannot report upload progress.

export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    readonly details?: unknown,
  ) {
    super(message);
  }
}

let csrfToken: string | null = null;
let unauthenticated: (() => void) | null = null;

export function setCsrf(token: string | null): void {
  csrfToken = token;
}

export function onUnauthenticated(fn: () => void): void {
  unauthenticated = fn;
}

export type Query = Record<string, string | number | boolean | null | undefined | readonly (string | number)[]>;

export function qs(q?: Query): string {
  if (!q) return '';
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(q)) {
    if (v === null || v === undefined || v === '' || v === false) continue;
    if (Array.isArray(v)) {
      if (v.length) p.set(k, v.join(','));
    } else p.set(k, v === true ? '1' : String(v));
  }
  const s = p.toString();
  return s ? `?${s}` : '';
}

function errorFrom(status: number, data: unknown): ApiError {
  const err = (data as { error?: { code?: string; message?: string; details?: unknown } } | null)?.error;
  return new ApiError(status, err?.code ?? `http-${status}`, err?.message ?? `Request failed (HTTP ${status}).`, err?.details);
}

export async function request<T>(method: string, path: string, body?: unknown, signal?: AbortSignal): Promise<T> {
  const headers: Record<string, string> = { accept: 'application/json' };
  if (body !== undefined) headers['content-type'] = 'application/json';
  if (method !== 'GET' && csrfToken) headers['x-csrf-token'] = csrfToken;
  let res: Response;
  try {
    res = await fetch(path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body), credentials: 'same-origin', signal });
  } catch (e) {
    if ((e as Error).name === 'AbortError') throw e;
    throw new ApiError(0, 'network', 'The server could not be reached. Check that the platform is running.');
  }
  const type = res.headers.get('content-type') ?? '';
  const data: unknown = type.includes('application/json') ? await res.json().catch(() => null) : await res.text().catch(() => null);
  if (!res.ok) {
    if (res.status === 401 && unauthenticated && !path.startsWith('/api/auth/')) unauthenticated();
    throw errorFrom(res.status, data);
  }
  return data as T;
}

export const api = {
  get: <T>(path: string, q?: Query, signal?: AbortSignal): Promise<T> => request<T>('GET', path + qs(q), undefined, signal),
  post: <T>(path: string, body: unknown = {}): Promise<T> => request<T>('POST', path, body),
  patch: <T>(path: string, body: unknown): Promise<T> => request<T>('PATCH', path, body),
  del: <T>(path: string, body?: unknown): Promise<T> => request<T>('DELETE', path, body ?? {}),
};

export interface UploadHandle<T> {
  promise: Promise<T>;
  abort: () => void;
}

/** Multipart upload with progress. Field order: the note first, then the files. */
export function uploadFiles<T>(path: string, files: File[], fields: Record<string, string>, onProgress: (loaded: number, total: number) => void): UploadHandle<T> {
  const xhr = new XMLHttpRequest();
  const promise = new Promise<T>((resolve, reject) => {
    xhr.open('POST', path);
    xhr.responseType = 'json';
    xhr.setRequestHeader('accept', 'application/json');
    if (csrfToken) xhr.setRequestHeader('x-csrf-token', csrfToken);
    xhr.upload.onprogress = (e) => {
      if (e.lengthComputable) onProgress(e.loaded, e.total);
    };
    xhr.onload = () => {
      if (xhr.status >= 200 && xhr.status < 300) resolve(xhr.response as T);
      else {
        if (xhr.status === 401 && unauthenticated) unauthenticated();
        reject(errorFrom(xhr.status, xhr.response));
      }
    };
    xhr.onerror = () => reject(new ApiError(0, 'network', 'The upload was interrupted (network error). Nothing partial is kept for files the server did not acknowledge; retry the batch.'));
    xhr.onabort = () => reject(new ApiError(0, 'aborted', 'Upload cancelled.'));
    const fd = new FormData();
    for (const [k, v] of Object.entries(fields)) fd.append(k, v);
    for (const f of files) fd.append('files', f, f.name);
    xhr.send(fd);
  });
  return { promise, abort: () => xhr.abort() };
}
