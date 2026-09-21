// Gmail adapter: the ONLY module that knows Gmail's DOM. Everything else speaks in message ids.
// Selectors are layered with fallbacks so a Gmail redesign degrades gracefully instead of breaking.

const ID_RE = /^[0-9a-f]{8,24}$/i;

export function isValidId(id: string | null | undefined): id is string {
  return !!id && ID_RE.test(id);
}

/** Expanded (readable) messages currently on screen. */
export function openMessages(): HTMLElement[] {
  const out: HTMLElement[] = [];
  for (const el of document.querySelectorAll<HTMLElement>('div[data-legacy-message-id]')) {
    if (!isValidId(el.getAttribute('data-legacy-message-id'))) continue;
    if (!bodyOf(el)) continue; // collapsed message: no body rendered
    if (el.closest('[data-mailshark-host]')) continue;
    out.push(el);
  }
  return out;
}

export function messageId(el: HTMLElement): string | null {
  const id = el.getAttribute('data-legacy-message-id');
  return isValidId(id) ? id.toLowerCase() : null;
}

export function currentThreadId(): string | null {
  const el = document.querySelector('h2[data-legacy-thread-id]') ?? document.querySelector('[data-legacy-thread-id][data-thread-perm-id]');
  const id = el?.getAttribute('data-legacy-thread-id');
  return isValidId(id) ? id.toLowerCase() : null;
}

export function bodyOf(el: HTMLElement): HTMLElement | null {
  return el.querySelector<HTMLElement>('div.a3s') ?? el.querySelector<HTMLElement>('div.ii.gt div[dir]');
}

/** Where to mount the verdict banner: just above the message body. */
export function bannerAnchor(el: HTMLElement): { parent: HTMLElement; before: Node | null } | null {
  const bodyWrap = el.querySelector<HTMLElement>('div.ii.gt') ?? bodyOf(el);
  if (bodyWrap?.parentElement) return { parent: bodyWrap.parentElement, before: bodyWrap };
  return { parent: el, before: el.firstChild };
}

/** Rows of the conversation list. */
export function listRows(): HTMLElement[] {
  return [...document.querySelectorAll<HTMLElement>('tr.zA')];
}

export function rowMessageId(row: HTMLElement): string | null {
  const last = row.querySelector('[data-legacy-last-message-id]')?.getAttribute('data-legacy-last-message-id');
  if (isValidId(last)) return last.toLowerCase();
  const thread = row.querySelector('[data-legacy-thread-id]')?.getAttribute('data-legacy-thread-id');
  return isValidId(thread) ? thread.toLowerCase() : null;
}

export function rowBadgeAnchor(row: HTMLElement): HTMLElement | null {
  return row.querySelector<HTMLElement>('.y6') ?? row.querySelector<HTMLElement>('.bog')?.parentElement ?? row.querySelector<HTMLElement>('.xT');
}

export function isInsideMessageBody(node: Element): HTMLElement | null {
  const body = node.closest<HTMLElement>('div.a3s');
  if (!body) return null;
  return body.closest<HTMLElement>('div[data-legacy-message-id]');
}

export class GmailFetchError extends Error {}

/**
 * Fetch the original RFC 822 message: the same endpoint as Gmail's own "Download message".
 * Runs in the page's origin with the user's session; the bytes stay in memory.
 */
export async function fetchRaw(id: string, signal?: AbortSignal): Promise<string> {
  if (!isValidId(id)) throw new GmailFetchError('Invalid message id');
  const url = `${location.origin}${location.pathname}?view=att&th=${id}&attid=0&disp=comp&safe=1&zw`;
  let res: Response;
  try {
    res = await fetch(url, { credentials: 'include', cache: 'no-store', ...(signal ? { signal } : {}) });
  } catch (e) {
    throw new GmailFetchError(e instanceof Error && e.name === 'AbortError' ? 'Cancelled' : 'Could not reach Gmail');
  }
  if (!res.ok) throw new GmailFetchError(`Gmail refused the request (HTTP ${res.status})`);
  const buf = new Uint8Array(await res.arrayBuffer());
  if (buf.length === 0) throw new GmailFetchError('Gmail returned an empty message');
  let raw = '';
  const CHUNK = 0x8000;
  for (let i = 0; i < buf.length; i += CHUNK) raw += String.fromCharCode.apply(null, Array.from(buf.subarray(i, i + CHUNK)));
  const head = raw.slice(0, 4096);
  if (/^\s*<(!doctype|html)/i.test(head) || !/^[A-Za-z][A-Za-z0-9-]*:/m.test(head) || !/^(from|received|date|message-id|subject|return-path|delivered-to|mime-version):/im.test(head)) {
    throw new GmailFetchError('Gmail did not return the original message');
  }
  return raw;
}

/** Background colour luminance behind an element (0 dark … 1 light). */
export function backgroundLuminance(el: Element | null): number {
  let node: Element | null = el;
  while (node && node !== document.documentElement) {
    const bg = getComputedStyle(node).backgroundColor;
    const m = /rgba?\((\d+),\s*(\d+),\s*(\d+)(?:,\s*([\d.]+))?\)/.exec(bg);
    if (m && (m[4] === undefined || Number(m[4]) > 0.5)) {
      const [r, g, b] = [Number(m[1]), Number(m[2]), Number(m[3])].map((v) => {
        const c = v / 255;
        return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
      }) as [number, number, number];
      return 0.2126 * r + 0.7152 * g + 0.0722 * b;
    }
    node = node.parentElement;
  }
  return 1;
}
