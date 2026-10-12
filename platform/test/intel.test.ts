// Intelligence store semantics and connector parsing (network mocked with recorded payloads).
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { zipSync, strToU8 } from 'fflate';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { IntelStore } from '../server/intel/store';
import { canonicalUrl, hostCandidates, urlWithoutQuery } from '../server/intel/normalize';
import { connector, mispIndicators, parseCsvLine } from '../server/intel/sources';
import { runSync } from '../server/intel/sync';
import { fetchResource, HttpError } from '../server/intel/http';
import { loadConfig } from '../server/config';

const tmp = (): string => mkdtempSync(join(tmpdir(), 'ms-intel-'));
const cfg = loadConfig({ dataDir: tmp() }).intel;

function freshStore(): IntelStore {
  const s = new IntelStore(join(tmp(), 'intel.db'));
  for (const id of ['phishing-database', 'urlhaus', 'threatfox', 'circl-osint', 'spamhaus-drop', 'tor-exits', 'openphish']) s.ensureSource(id, true);
  s.replacePopular([['google.com', 1], ['angelfire.com', 3245], ['example-legit.com', 900_000]]);
  return s;
}

describe('normalisation', () => {
  it('canonicalises URLs and hosts the same way for feeds and evidence', () => {
    expect(canonicalUrl('HTTP://Evil.Example:80/Login?a=1#frag')).toBe('http://evil.example/Login?a=1');
    expect(canonicalUrl('https://evil.example/')).toBe('https://evil.example');
    expect(canonicalUrl('evil.example/path')).toBe('http://evil.example/path');
    expect(canonicalUrl('javascript:alert(1)')).toBeNull();
    expect(urlWithoutQuery('https://evil.example/login/?u=1')).toBe('https://evil.example/login');
    expect(hostCandidates('www.a.b.evil.co.uk')).toEqual(['a.b.evil.co.uk', 'b.evil.co.uk', 'evil.co.uk']);
  });

  it('parses abuse.ch CSV lines, including quoted commas and spaced fields', () => {
    expect(parseCsvLine('"1","2026-10-12 15:23:13","http://x/a,b","online","","malware_download","elf,Mozi","https://urlhaus.abuse.ch/url/1/","r"')).toEqual(['1', '2026-10-12 15:23:13', 'http://x/a,b', 'online', '', 'malware_download', 'elf,Mozi', 'https://urlhaus.abuse.ch/url/1/', 'r']);
    expect(parseCsvLine('"2026-10-12 14:32:34", "abc", "n/a"')).toEqual(['2026-10-12 14:32:34', 'abc', 'n/a']);
  });

  it('maps MISP attributes to attacker-side indicators only', () => {
    expect(mispIndicators({ type: 'url', value: 'https://evil.example/x' })).toEqual([{ type: 'url', value: 'https://evil.example/x' }]);
    expect(mispIndicators({ type: 'link', value: 'https://report.example/blog' })).toEqual([]);
    expect(mispIndicators({ type: 'url', category: 'External analysis', value: 'https://report.example/blog' })).toEqual([]);
    expect(mispIndicators({ type: 'domain|ip', value: 'evil.example|203.0.113.5' })).toEqual([{ type: 'domain', value: 'evil.example' }, { type: 'ip', value: '203.0.113.5' }]);
    expect(mispIndicators({ type: 'filename|sha256', value: `invoice.zip|${'a'.repeat(64)}` })).toEqual([{ type: 'sha256', value: 'a'.repeat(64) }, { type: 'filename', value: 'invoice.zip' }]);
    expect(mispIndicators({ type: 'target-email', value: 'victim@example.org' })).toEqual([]);
  });
});

describe('intelligence store lookups', () => {
  it('matches URLs exactly, then without the query string, then by listed URLs on the same host', () => {
    const s = freshStore();
    s.replaceIndicators('urlhaus', [{ type: 'url', value: 'http://evil.example/payload.exe', threat: 'malware_download', family: 'Emotet' }]);
    expect(s.lookupUrl('HTTP://EVIL.example/payload.exe')[0]).toMatchObject({ matchType: 'exact-url', family: 'Emotet' });
    expect(s.lookupUrl('http://evil.example/payload.exe?utm=1')[0]?.matchType).toBe('url-without-query');
    expect(s.listedUrlsOnHost('evil.example')[0]?.matchType).toBe('host-of-listed-url');
    expect(s.lookupUrl('http://evil.example/other')).toHaveLength(0);
  });

  it('matches host-level listings on the host and its parents, and suppresses popular or shared apexes', () => {
    const s = freshStore();
    s.replaceIndicators('phishing-database', [
      { type: 'domain', value: 'paypa1-login.example' },
      { type: 'domain', value: 'angelfire.com' },
      { type: 'domain', value: 'weebly.com' },
      { type: 'domain', value: 'evil-tenant.weebly.com' },
    ]);
    expect(s.lookupHost('secure.paypa1-login.example')[0]).toMatchObject({ matchType: 'parent-domain', suppressed: null });
    expect(s.lookupHost('www.angelfire.com')[0]).toMatchObject({ matchType: 'host', suppressed: 'popular-domain' });
    expect(s.lookupHost('innocent.weebly.com').find((h) => h.value === 'weebly.com')?.suppressed).toBe('shared-platform');
    expect(s.lookupHost('evil-tenant.weebly.com').find((h) => h.value === 'evil-tenant.weebly.com')?.suppressed).toBeNull();
  });

  it('matches IPs exactly and inside DROP ranges; Tor exits are context, not threats', () => {
    const s = freshStore();
    s.replaceCidrs('spamhaus-drop', [{ start: 0xcb007100, end: 0xcb0071ff, cidr: '203.0.113.0/24', label: 'SBL1', reference: null }]);
    s.replaceIndicators('tor-exits', [{ type: 'ip', value: '198.51.100.7', threat: 'tor-exit' }]);
    expect(s.lookupIp('203.0.113.77')[0]).toMatchObject({ matchType: 'cidr', value: '203.0.113.0/24' });
    expect(s.lookupIp('198.51.100.7')[0]?.threat).toBe('tor-exit');
    expect(s.lookupIp('192.0.2.1')).toHaveLength(0);
  });

  it('finds documented events by indicator and ignores disabled sources', () => {
    const s = freshStore();
    s.upsertEvent('circl-osint', { id: 'ev-1', name: 'Phishing campaign against hotel guests', date: Date.UTC(2026, 5, 1), updatedAt: null, org: 'CIRCL', tags: ['tlp:clear'], threatLevel: 3, reference: 'https://example.org/report', indicators: [{ type: 'domain', value: 'booking-guest-verify.example', category: 'Network activity', toIds: true, comment: null }] });
    expect(s.lookupEvents('domain', 'www.booking-guest-verify.example')[0]).toMatchObject({ eventId: 'ev-1', name: 'Phishing campaign against hotel guests', toIds: true });
    s.setEnabled('circl-osint', false);
    expect(s.lookupEvents('domain', 'booking-guest-verify.example')).toHaveLength(0);
  });

  it('identifies the intelligence state with a snapshot id that changes when a source updates', () => {
    const s = freshStore();
    const a = s.snapshotId();
    s.updateSource('urlhaus', { last_success: 123, snapshot_sha256: 'x' });
    expect(s.snapshotId()).not.toBe(a);
  });
});

describe('connectors (recorded payloads, mocked network)', () => {
  afterEach(() => vi.unstubAllGlobals());
  const respond = (body: Uint8Array | string, headers: Record<string, string> = {}): Response => new Response(typeof body === 'string' ? body : Buffer.from(body), { status: 200, headers });

  it('URLhaus: parses the CSV dump inside the zip', async () => {
    const csv = '################\n# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter\n"9","2026-10-12 15:23:13","http://203.0.113.9:8080/bin.sh","online","2026-10-12 15:23:13","malware_download","elf,Mozi","https://urlhaus.abuse.ch/url/9/","r"\n';
    vi.stubGlobal('fetch', vi.fn(async () => respond(zipSync({ 'csv.txt': strToU8(csv) }), { etag: '"v1"' })));
    const s = freshStore();
    const r = await runSync(s, connector('urlhaus')!, cfg);
    expect(r.status).toBe('updated');
    expect(s.lookupUrl('http://203.0.113.9:8080/bin.sh')[0]).toMatchObject({ source: 'urlhaus', threat: 'malware_download', tags: 'elf,Mozi', externalId: '9' });
    expect(s.sourceRow('urlhaus')?.etag).toBe('"v1"');
  });

  it('ThreatFox: keeps the malware family, confidence and reference', async () => {
    const json = JSON.stringify({ '42': [{ ioc_value: 'bad-c2.example', ioc_type: 'domain', threat_type: 'botnet_cc', malware_printable: 'Lumma Stealer', malware_alias: 'LummaC2', first_seen_utc: '2026-10-01 10:00:00', last_seen_utc: null, confidence_level: 75, reference: null, tags: 'stealer' }] });
    vi.stubGlobal('fetch', vi.fn(async () => respond(zipSync({ 'full.json': strToU8(json) }))));
    const s = freshStore();
    await runSync(s, connector('threatfox')!, cfg);
    expect(s.lookupHost('bad-c2.example')[0]).toMatchObject({ family: 'Lumma Stealer', confidence: 75, reference: 'https://threatfox.abuse.ch/ioc/42/' });
  });

  it('MISP feed: imports events with attributes and object attributes, and resumes in batches', async () => {
    const manifest = { 'uuid-1': { info: 'Phishing kit wave', date: '2026-06-01', timestamp: '1780000000' }, 'uuid-old': { info: 'Old', date: '2010-01-01', timestamp: '1260000000' } };
    const event = { Event: { uuid: 'uuid-1', info: 'Phishing kit wave', date: '2026-06-01', timestamp: '1780000000', Orgc: { name: 'CIRCL' }, Tag: [{ name: 'tlp:clear' }], Attribute: [{ type: 'domain', value: 'kit-wave.example', to_ids: true, category: 'Network activity' }], Object: [{ Attribute: [{ type: 'url', value: 'https://kit-wave.example/o365/login.php', to_ids: true, category: 'Network activity' }, { type: 'link', value: 'https://blog.example/analysis', category: 'External analysis' }] }] } };
    const fetchMock = vi.fn(async (url: URL | string) => respond(String(url).endsWith('manifest.json') ? JSON.stringify(manifest) : JSON.stringify(event)));
    vi.stubGlobal('fetch', fetchMock);
    const s = freshStore();
    const r = await runSync(s, connector('circl-osint')!, cfg);
    expect(r.status).toBe('updated');
    const hits = s.lookupEvents('url', 'https://kit-wave.example/o365/login.php');
    expect(hits[0]).toMatchObject({ eventId: 'uuid-1', name: 'Phishing kit wave', org: 'CIRCL', reference: 'https://blog.example/analysis' });
    expect(fetchMock.mock.calls.some((c) => String(c[0]).includes('uuid-old'))).toBe(false); // older than MAILSHARK_MISP_FEED_SINCE
  });

  it('a failing source keeps its previous data and reports the error', async () => {
    const s = freshStore();
    s.replaceIndicators('openphish', [{ type: 'url', value: 'https://kept.example/login' }]);
    vi.stubGlobal('fetch', vi.fn(async () => new Response('down', { status: 503 })));
    const r = await runSync(s, connector('openphish')!, cfg, () => undefined);
    expect(r.status).toBe('error');
    expect(s.sourceRow('openphish')?.last_error).toMatch(/503/);
    expect(s.lookupUrl('https://kept.example/login')).toHaveLength(1);
  }, 60_000);

  it('the HTTP client refuses hosts outside the connector allowlist (SSRF guard), even via redirects', async () => {
    await expect(fetchResource('https://169.254.169.254/latest/meta-data', { allowedHosts: ['urlhaus.abuse.ch'] })).rejects.toBeInstanceOf(HttpError);
    vi.stubGlobal('fetch', vi.fn(async () => new Response(null, { status: 302, headers: { location: 'http://127.0.0.1:8080/admin' } })));
    await expect(fetchResource('https://urlhaus.abuse.ch/downloads/csv/', { allowedHosts: ['urlhaus.abuse.ch'], retries: 0 })).rejects.toThrow(/refused/);
  });
});
