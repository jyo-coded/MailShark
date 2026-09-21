// Threat-feed lookups via Bloom filters. Feeds are downloaded as whole filters and checked
// locally, so no domain from the user's mail ever leaves the device.
// Bit layout and hashing must match feeds/build_feeds.py exactly.
import type { IntelProvider } from '../types';
import { murmur3 } from '../util/hash';
import { hostInfo } from '../util/domain';

export const BLOOM_SEED_1 = 0x9747b28c;
export const BLOOM_SEED_2 = 0x5bd1e995;

export interface BloomMeta {
  name: string;
  m: number; // bits
  k: number; // hash functions
  count: number;
}

export class BloomFilter {
  constructor(
    readonly meta: BloomMeta,
    private readonly bits: Uint8Array,
  ) {
    if (bits.length * 8 < meta.m) throw new Error(`Bloom filter ${meta.name}: expected ${meta.m} bits, got ${bits.length * 8}`);
  }

  has(value: string): boolean {
    const h1 = murmur3(value, BLOOM_SEED_1);
    const h2 = murmur3(value, BLOOM_SEED_2) | 1;
    const m = this.meta.m;
    for (let i = 0; i < this.meta.k; i++) {
      const idx = (h1 + i * (h2 >>> 0)) % m;
      if (((this.bits[idx >>> 3] as number) & (1 << (idx & 7))) === 0) return false;
    }
    return true;
  }
}

export function normalizeFeedHost(host: string): string {
  return host.trim().toLowerCase().replace(/\.$/, '').replace(/^www\./, '');
}

/** Candidate names to test for a host: the host itself, then parents down to the registrable domain. */
export function hostCandidates(hostRaw: string): string[] {
  const host = normalizeFeedHost(hostRaw);
  const info = hostInfo(host);
  if (info.isIp) return [host];
  const reg = info.regDomain;
  const out = [host];
  if (!reg) return out;
  const labels = host.split('.');
  for (let i = 1; i < labels.length; i++) {
    const cand = labels.slice(i).join('.');
    if (cand.length < reg.length) break;
    out.push(cand);
  }
  return [...new Set(out)];
}

export class BloomIntel implements IntelProvider {
  constructor(private readonly filters: BloomFilter[]) {}

  get size(): number {
    return this.filters.reduce((n, f) => n + f.meta.count, 0);
  }

  lookupDomain(domain: string): string | null {
    if (!domain) return null;
    for (const cand of hostCandidates(domain)) {
      for (const f of this.filters) if (f.has(cand)) return f.meta.name;
    }
    return null;
  }
}
