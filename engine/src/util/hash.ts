// Hashing primitives. Crypto-grade digests use WebCrypto (browser + Node ≥ 19);
// MD5 is implemented here because WebCrypto deliberately omits it.

function toHex(buf: ArrayBuffer | Uint8Array): string {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let out = '';
  for (let i = 0; i < bytes.length; i++) out += (bytes[i] as number).toString(16).padStart(2, '0');
  return out;
}

function asBufferSource(bytes: Uint8Array): ArrayBuffer {
  // Copy into a standalone ArrayBuffer so SharedArrayBuffer-backed views are never passed to digest().
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}

export async function sha256Hex(bytes: Uint8Array): Promise<string> {
  return toHex(await crypto.subtle.digest('SHA-256', asBufferSource(bytes)));
}

export async function sha1Hex(bytes: Uint8Array): Promise<string> {
  return toHex(await crypto.subtle.digest('SHA-1', asBufferSource(bytes)));
}

// ── MD5 (RFC 1321) ──────────────────────────────────────────────────────────

const MD5_S = [
  7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 4, 11,
  16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];
const MD5_K = new Uint32Array(64);
for (let i = 0; i < 64; i++) MD5_K[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 2 ** 32) >>> 0;

export function md5Hex(input: Uint8Array): string {
  const len = input.length;
  const padded = new Uint8Array((((len + 8) >>> 6) + 1) << 6);
  padded.set(input);
  padded[len] = 0x80;
  const bitLen = len * 8;
  const view = new DataView(padded.buffer);
  view.setUint32(padded.length - 8, bitLen >>> 0, true);
  view.setUint32(padded.length - 4, Math.floor(bitLen / 2 ** 32) >>> 0, true);

  let a0 = 0x67452301;
  let b0 = 0xefcdab89;
  let c0 = 0x98badcfe;
  let d0 = 0x10325476;
  const m = new Uint32Array(16);

  for (let off = 0; off < padded.length; off += 64) {
    for (let j = 0; j < 16; j++) m[j] = view.getUint32(off + j * 4, true);
    let a = a0;
    let b = b0;
    let c = c0;
    let d = d0;
    for (let i = 0; i < 64; i++) {
      let f: number;
      let g: number;
      if (i < 16) {
        f = (b & c) | (~b & d);
        g = i;
      } else if (i < 32) {
        f = (d & b) | (~d & c);
        g = (5 * i + 1) % 16;
      } else if (i < 48) {
        f = b ^ c ^ d;
        g = (3 * i + 5) % 16;
      } else {
        f = c ^ (b | ~d);
        g = (7 * i) % 16;
      }
      const tmp = d;
      d = c;
      c = b;
      const sum = (a + f + (MD5_K[i] as number) + (m[g] as number)) >>> 0;
      const s = MD5_S[i] as number;
      b = (b + ((sum << s) | (sum >>> (32 - s)))) >>> 0;
      a = tmp;
    }
    a0 = (a0 + a) >>> 0;
    b0 = (b0 + b) >>> 0;
    c0 = (c0 + c) >>> 0;
    d0 = (d0 + d) >>> 0;
  }
  const out = new Uint8Array(16);
  const ov = new DataView(out.buffer);
  ov.setUint32(0, a0, true);
  ov.setUint32(4, b0, true);
  ov.setUint32(8, c0, true);
  ov.setUint32(12, d0, true);
  return toHex(out);
}

// ── Fast non-cryptographic hashes ───────────────────────────────────────────

/** FNV-1a 32-bit over the UTF-16 code units of a string. */
export function fnv1a32(str: string, seed = 0x811c9dc5): number {
  let h = seed >>> 0;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h >>> 0;
}

/** 53-bit string hash (cyrb53) rendered as 14 hex chars; stable across engines. */
export function hash53(str: string, seed = 0): string {
  let h1 = 0xdeadbeef ^ seed;
  let h2 = 0x41c6ce57 ^ seed;
  for (let i = 0; i < str.length; i++) {
    const ch = str.charCodeAt(i);
    h1 = Math.imul(h1 ^ ch, 2654435761);
    h2 = Math.imul(h2 ^ ch, 1597334677);
  }
  h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507);
  h1 ^= Math.imul(h2 ^ (h2 >>> 13), 3266489909);
  h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507);
  h2 ^= Math.imul(h1 ^ (h1 >>> 13), 3266489909);
  const n = 4294967296 * (2097151 & h2) + (h1 >>> 0);
  return n.toString(16).padStart(14, '0');
}

/**
 * MurmurHash3 x86 32-bit over UTF-8 bytes. Used by the threat-feed Bloom filter;
 * the Python feed builder implements the identical function (see feeds/build_feeds.py).
 */
export function murmur3(str: string, seed = 0): number {
  const bytes = new TextEncoder().encode(str);
  let h = seed >>> 0;
  const c1 = 0xcc9e2d51;
  const c2 = 0x1b873593;
  const nblocks = bytes.length >>> 2;
  for (let i = 0; i < nblocks; i++) {
    const o = i * 4;
    let k =
      (bytes[o] as number) | ((bytes[o + 1] as number) << 8) | ((bytes[o + 2] as number) << 16) | ((bytes[o + 3] as number) << 24);
    k = Math.imul(k, c1);
    k = (k << 15) | (k >>> 17);
    k = Math.imul(k, c2);
    h ^= k;
    h = (h << 13) | (h >>> 19);
    h = (Math.imul(h, 5) + 0xe6546b64) >>> 0;
  }
  const rem = bytes.length & 3;
  if (rem > 0) {
    const tail = nblocks * 4;
    let k1 = 0;
    if (rem >= 3) k1 ^= (bytes[tail + 2] as number) << 16;
    if (rem >= 2) k1 ^= (bytes[tail + 1] as number) << 8;
    k1 ^= bytes[tail] as number;
    k1 = Math.imul(k1, c1);
    k1 = (k1 << 15) | (k1 >>> 17);
    k1 = Math.imul(k1, c2);
    h ^= k1;
  }
  h ^= bytes.length;
  h ^= h >>> 16;
  h = Math.imul(h, 0x85ebca6b);
  h ^= h >>> 13;
  h = Math.imul(h, 0xc2b2ae35);
  h ^= h >>> 16;
  return h >>> 0;
}

// ── Similarity sketches ─────────────────────────────────────────────────────

export const MINHASH_PERMUTATIONS = 64;
export const LSH_BANDS = 16;
const LSH_ROWS = MINHASH_PERMUTATIONS / LSH_BANDS;

function mix32(x: number): number {
  x = Math.imul(x ^ (x >>> 16), 0x7feb352d);
  x = Math.imul(x ^ (x >>> 15), 0x846ca68b);
  return (x ^ (x >>> 16)) >>> 0;
}

const MINHASH_SEEDS: number[] = [];
for (let i = 0; i < MINHASH_PERMUTATIONS; i++) MINHASH_SEEDS.push(mix32(0x9e3779b9 + i * 0x632be5ab));

export function shingles(tokens: string[], size = 3, cap = 4000): string[] {
  if (tokens.length === 0) return [];
  if (tokens.length < size) return [tokens.join(' ')];
  const out = new Set<string>();
  for (let i = 0; i + size <= tokens.length && out.size < cap; i++) out.add(tokens.slice(i, i + size).join(' '));
  return [...out];
}

export function minhash(features: string[]): number[] {
  const sig = new Array<number>(MINHASH_PERMUTATIONS).fill(0xffffffff);
  if (features.length === 0) return sig.map(() => 0);
  for (const f of features) {
    const base = fnv1a32(f);
    for (let i = 0; i < MINHASH_PERMUTATIONS; i++) {
      const v = mix32(base ^ (MINHASH_SEEDS[i] as number));
      if (v < (sig[i] as number)) sig[i] = v;
    }
  }
  return sig;
}

export function minhashSimilarity(a: number[], b: number[]): number {
  if (a.length !== b.length || a.length === 0) return 0;
  if (a.every((v) => v === 0) || b.every((v) => v === 0)) return 0;
  let eq = 0;
  for (let i = 0; i < a.length; i++) if (a[i] === b[i]) eq++;
  return eq / a.length;
}

export function lshBandKeys(sig: number[]): string[] {
  if (sig.every((v) => v === 0)) return [];
  const keys: string[] = [];
  for (let b = 0; b < LSH_BANDS; b++) {
    const slice = sig.slice(b * LSH_ROWS, (b + 1) * LSH_ROWS).join('.');
    keys.push(`lsh:${b}:${hash53(slice)}`);
  }
  return keys;
}

/** 64-bit SimHash rendered as 16 hex chars. */
export function simhash(features: string[]): string {
  const v = new Array<number>(64).fill(0);
  for (const f of features) {
    const lo = fnv1a32(f);
    const hi = fnv1a32(f, 0x01000193 ^ 0x5bd1e995);
    for (let i = 0; i < 32; i++) {
      v[i] = (v[i] as number) + ((lo >>> i) & 1 ? 1 : -1);
      v[i + 32] = (v[i + 32] as number) + ((hi >>> i) & 1 ? 1 : -1);
    }
  }
  let lo = 0;
  let hi = 0;
  for (let i = 0; i < 32; i++) {
    if ((v[i] as number) > 0) lo |= 1 << i;
    if ((v[i + 32] as number) > 0) hi |= 1 << i;
  }
  return (hi >>> 0).toString(16).padStart(8, '0') + (lo >>> 0).toString(16).padStart(8, '0');
}

export function simhashSimilarity(a: string, b: string): number {
  if (a.length !== 16 || b.length !== 16) return 0;
  let dist = 0;
  for (let i = 0; i < 16; i += 8) {
    let x = (parseInt(a.slice(i, i + 8), 16) ^ parseInt(b.slice(i, i + 8), 16)) >>> 0;
    while (x) {
      dist += x & 1;
      x >>>= 1;
    }
  }
  return 1 - dist / 64;
}
