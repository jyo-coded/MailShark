// Text helpers shared by the analyzers.

export const ZERO_WIDTH_RE = /[​-‍⁠﻿­͏᠎]|[\u{E0000}-\u{E007F}\u{E0100}-\u{E01EF}]/gu;

/** Invisible "tag" characters and variation selectors smuggled into names ("Ꮇ󠄹icrosoft"). */
export const INVISIBLE_RE = /[​-‍⁠᠎]|[\u{E0000}-\u{E007F}\u{E0100}-\u{E01EF}]/u;

/** Mathematical alphanumeric "fonts" (𝐏𝐋𝐄𝐀𝐒𝐄) used to slip words past filters. */
export const STYLED_LETTERS_RE = /[\u{1D400}-\u{1D7FF}]/u;

// Cherokee and other letters that render like Latin capitals.
const EXOTIC_CONFUSABLES: Record<string, string> = {
  Ꭺ: 'A', Ᏼ: 'B', Ꮯ: 'C', Ꭰ: 'D', Ꭼ: 'E', Ꮐ: 'G', Ꮋ: 'H', Ꭵ: 'i', Ꭻ: 'J', Ꮶ: 'K', Ꮮ: 'L', Ꮇ: 'M', Ꮲ: 'P', Ꭱ: 'R', Ꮪ: 'S', Ꭲ: 'T', Ꮩ: 'V', Ꮃ: 'W', Ꮓ: 'Z',
};

/** Strip invisible characters and fold exotic look-alike letters and styled fonts to plain ASCII. */
export function deobfuscate(s: string): string {
  let out = '';
  for (const ch of s.replace(ZERO_WIDTH_RE, '')) out += EXOTIC_CONFUSABLES[ch] ?? ch;
  return out.normalize('NFKC');
}

/** Decode bytes as Latin-1 so every byte maps to exactly one char (binary-safe). */
export function latin1(bytes: Uint8Array, max = bytes.length): string {
  const n = Math.min(max, bytes.length);
  let out = '';
  const CHUNK = 0x8000;
  for (let i = 0; i < n; i += CHUNK) {
    out += String.fromCharCode.apply(null, Array.from(bytes.subarray(i, Math.min(n, i + CHUNK))));
  }
  return out;
}

export function latin1ToBytes(str: string): Uint8Array {
  const out = new Uint8Array(str.length);
  for (let i = 0; i < str.length; i++) out[i] = str.charCodeAt(i) & 0xff;
  return out;
}

export function collapseWs(s: string): string {
  return s.replace(/\s+/g, ' ').trim();
}

export function truncate(s: string, n: number): string {
  return s.length <= n ? s : s.slice(0, Math.max(0, n - 1)) + '…';
}

export function countZeroWidth(s: string): number {
  const m = s.match(ZERO_WIDTH_RE);
  return m ? m.length : 0;
}

/** Shannon entropy in bits per symbol over (at most) the first 64 KiB. */
export function byteEntropy(bytes: Uint8Array): number {
  const n = Math.min(bytes.length, 65536);
  if (n === 0) return 0;
  const freq = new Uint32Array(256);
  for (let i = 0; i < n; i++) {
    const b = bytes[i] as number;
    freq[b] = (freq[b] as number) + 1;
  }
  let e = 0;
  for (let i = 0; i < 256; i++) {
    const c = freq[i] as number;
    if (c) {
      const p = c / n;
      e -= p * Math.log2(p);
    }
  }
  return Math.round(e * 1000) / 1000;
}

export function stringEntropy(s: string): number {
  if (!s) return 0;
  const freq = new Map<string, number>();
  for (const ch of s) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  let e = 0;
  for (const c of freq.values()) {
    const p = c / s.length;
    e -= p * Math.log2(p);
  }
  return e;
}

/** Lowercase, strip accents & zero-width chars, fold common leetspeak used to dodge keyword filters. */
export function normalizeForMatching(s: string): string {
  return deobfuscate(s)
    .normalize('NFKD')
    .replace(/[̀-ͯ]/g, '')
    .replace(ZERO_WIDTH_RE, '')
    .toLowerCase()
    .replace(/[’‘`´]/g, "'")
    .replace(/\s+/g, ' ');
}

export function tokenize(s: string): string[] {
  return normalizeForMatching(s)
    .split(/[^\p{L}\p{N}]+/u)
    .filter((t) => t.length > 1 && t.length < 40);
}

/** Replace volatile parts (numbers, ids, emails, urls, dates) with placeholders to expose the template. */
export function templatize(s: string): string {
  return collapseWs(
    s
      .replace(/https?:\/\/\S+/gi, '{url}')
      .replace(/[\w.+-]+@[\w-]+\.[\w.-]+/g, '{email}')
      .replace(/\b\d{1,2}[/.-]\d{1,2}[/.-]\d{2,4}\b/g, '{date}')
      .replace(/\b[a-f0-9]{8,}\b/gi, '{hex}')
      .replace(/\b(?=[A-Za-z0-9]*\d)(?=[A-Za-z0-9]*[A-Za-z])[A-Za-z0-9]{6,}\b/g, '{id}')
      .replace(/[#№]?\d[\d,.]*/g, '{n}')
      .toLowerCase(),
  );
}

export function uniq<T>(arr: Iterable<T>): T[] {
  return [...new Set(arr)];
}

export function jaccard<T>(a: T[] | Set<T>, b: T[] | Set<T>): number | null {
  const A = a instanceof Set ? a : new Set(a);
  const B = b instanceof Set ? b : new Set(b);
  if (A.size === 0 && B.size === 0) return null;
  let inter = 0;
  for (const x of A) if (B.has(x)) inter++;
  return inter / (A.size + B.size - inter);
}

export function levenshtein(a: string, b: string, max = 3): number {
  if (a === b) return 0;
  if (Math.abs(a.length - b.length) > max) return max + 1;
  let prev = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    const cur = [i];
    let rowMin = i;
    for (let j = 1; j <= b.length; j++) {
      const cost = a.charCodeAt(i - 1) === b.charCodeAt(j - 1) ? 0 : 1;
      const v = Math.min((prev[j] as number) + 1, (cur[j - 1] as number) + 1, (prev[j - 1] as number) + cost);
      cur.push(v);
      if (v < rowMin) rowMin = v;
    }
    if (rowMin > max) return max + 1;
    prev = cur;
  }
  return prev[b.length] as number;
}

export function scriptsOf(s: string): Set<string> {
  const out = new Set<string>();
  for (const ch of s) {
    if (/\p{Script=Latin}/u.test(ch)) out.add('Latin');
    else if (/\p{Script=Cyrillic}/u.test(ch)) out.add('Cyrillic');
    else if (/\p{Script=Greek}/u.test(ch)) out.add('Greek');
    else if (/\p{Script=Armenian}/u.test(ch)) out.add('Armenian');
    else if (/\p{Script=Han}/u.test(ch)) out.add('Han');
    else if (/\p{Script=Arabic}/u.test(ch)) out.add('Arabic');
    else if (/\p{Script=Hebrew}/u.test(ch)) out.add('Hebrew');
    else if (/\p{Script=Devanagari}/u.test(ch)) out.add('Devanagari');
    else if (/\p{Script=Cherokee}/u.test(ch)) out.add('Cherokee');
  }
  return out;
}

/** True when a single word mixes Latin with a script that has Latin look-alikes (classic homoglyph trick). */
export function hasMixedScriptWord(s: string): boolean {
  for (const word of s.split(/[\s.,;:!?'"()<>@/\\-]+/)) {
    if (word.length < 2) continue;
    const scripts = scriptsOf(word);
    if (scripts.has('Latin') && (scripts.has('Cyrillic') || scripts.has('Greek') || scripts.has('Armenian') || scripts.has('Cherokee'))) {
      return true;
    }
  }
  return false;
}
