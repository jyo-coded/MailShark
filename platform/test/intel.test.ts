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
import { externalMatches, isGenericName, seriesKey } from '../server/correlation/external';
import { loadConfig } from '../server/config';

const tmp = (): string => mkdtempSync(join(tmpdir(), 'ms-intel-'));
const cfg = loadConfig({ dataDir: tmp() }).intel;

function freshStore(): IntelStore {
  const s = new IntelStore(join(tmp(), 'intel.db'));
  for (const id of ['phishing-database', 'urlhaus', 'threatfox', 'circl-osint', 'spamhaus-drop', 'tor-exits', 'openphish', 'phishtank']) s.ensureSource(id, true);
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

describe('connectors (payloads in the providers’ documented formats, mocked network)', () => {
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

  it('OpenPhish: fetches the GitHub-hosted community feed', async () => {
    const fetchMock = vi.fn(async (_u: URL | string) => respond('https://phish-one.example/login\nhttps://phish-two.example/verify?x=1\n'));
    vi.stubGlobal('fetch', fetchMock);
    const s = freshStore();
    await runSync(s, connector('openphish')!, cfg);
    expect(String(fetchMock.mock.calls[0]?.[0])).toBe('https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt');
    expect(s.lookupUrl('https://phish-one.example/login')[0]).toMatchObject({ source: 'openphish', threat: 'phishing' });
  });

  it('PhishTank: maps verified entries with target brand and detail page', async () => {
    const list = [{ phish_id: 8812, url: 'https://paypa1-login.example/signin', phish_detail_url: 'http://www.phishtank.com/phish_detail.php?phish_id=8812', submission_time: '2026-10-11T08:00:00+00:00', verification_time: '2026-10-11T09:00:00+00:00', target: 'PayPal' }];
    const fetchMock = vi.fn(async (_u: URL | string) => respond(JSON.stringify(list)));
    vi.stubGlobal('fetch', fetchMock);
    const s = freshStore();
    await runSync(s, connector('phishtank')!, { ...cfg, phishtankAppKey: 'k' });
    expect(String(fetchMock.mock.calls[0]?.[0])).toBe('https://data.phishtank.com/data/k/online-valid.json');
    expect(s.lookupUrl('https://paypa1-login.example/signin')[0]).toMatchObject({ family: 'target: PayPal', externalId: '8812' });
  });

  it('Tor exit list: stored as context (tor-exit), never as a threat verdict', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => respond('185.220.101.1\n185.220.101.2\n')));
    const s = freshStore();
    await runSync(s, connector('tor-exits')!, cfg);
    expect(s.lookupIp('185.220.101.1')[0]).toMatchObject({ source: 'tor-exits', threat: 'tor-exit' });
  });

  it('OTX lookup: turns pulses into named external events (and reports none found)', async () => {
    const pulse = { pulse_info: { count: 1, pulses: [{ id: 'p1', name: 'Microsoft 365 AiTM phishing wave', created: '2026-09-30T10:00:00', modified: '2026-10-01T10:00:00', tags: ['aitm'], references: ['https://example-research.org/aitm'], adversary: 'Storm-0000', malware_families: [{ display_name: 'Tycoon2FA' }], author_name: 'AlienVault' }] } };
    const fetchMock = vi.fn(async (_u: URL | string) => respond(JSON.stringify(pulse)));
    vi.stubGlobal('fetch', fetchMock);
    const s = freshStore();
    const r = await connector('otx')!.lookup!({ store: s, config: cfg }, 'domain', 'login-m365.example');
    expect(String(fetchMock.mock.calls[0]?.[0])).toBe('https://otx.alienvault.com/api/v1/indicators/domain/login-m365.example/general');
    expect(r.status).toBe('found');
    expect(r.events[0]).toMatchObject({ id: 'p1', name: 'Microsoft 365 AiTM phishing wave', org: 'AlienVault' });
    expect(r.events[0]?.tags).toEqual(expect.arrayContaining(['adversary:Storm-0000', 'malware:Tycoon2FA']));
    vi.stubGlobal('fetch', vi.fn(async () => respond(JSON.stringify({ pulse_info: { count: 0, pulses: [] } }))));
    expect((await connector('otx')!.lookup!({ store: s, config: cfg }, 'ip', '198.51.100.7')).status).toBe('not-found');
  });

  it('VirusTotal lookup: engine counts, threat label and 404 as unknown', async () => {
    const body = { data: { attributes: { last_analysis_stats: { malicious: 7, suspicious: 1, harmless: 60 }, popular_threat_classification: { suggested_threat_label: 'trojan.formbook' }, tags: ['peexe'], first_submission_date: 1790000000, last_analysis_date: 1790100000 } } };
    const fetchMock = vi.fn(async (_u: URL | string) => respond(JSON.stringify(body)));
    vi.stubGlobal('fetch', fetchMock);
    const s = freshStore();
    const vcfg = { ...cfg, virusTotalApiKey: 'vt' };
    const r = await connector('virustotal')!.lookup!({ store: s, config: vcfg }, 'sha256', 'a'.repeat(64));
    expect(String(fetchMock.mock.calls[0]?.[0])).toBe(`https://www.virustotal.com/api/v3/files/${'a'.repeat(64)}`);
    expect(r.hits[0]).toMatchObject({ threat: 'malicious', family: 'trojan.formbook', confidence: 7 });
    vi.stubGlobal('fetch', vi.fn(async () => new Response('{"error":{"code":"NotFoundError"}}', { status: 404 })));
    expect((await connector('virustotal')!.lookup!({ store: s, config: vcfg }, 'domain', 'unknown.example')).status).toBe('not-found');
  }, 30_000);

  it('MISP instance lookup: events that contain the value, via restSearch on the configured host only', async () => {
    const body = { response: { Attribute: [{ event_id: '17', Event: { info: 'Invoice lure campaign', uuid: 'ev-uuid', date: '2026-09-02', Orgc: { name: 'Our SOC' } }, Tag: [{ name: 'tlp:amber' }] }] } };
    const fetchMock = vi.fn(async (_u: URL | string, _init?: RequestInit) => respond(JSON.stringify(body)));
    vi.stubGlobal('fetch', fetchMock);
    const s = freshStore();
    const mcfg = { ...cfg, mispUrl: 'https://misp.internal.example', mispApiKey: 'key' };
    const r = await connector('misp')!.lookup!({ store: s, config: mcfg }, 'email', 'billing@invoices.example');
    expect(String(fetchMock.mock.calls[0]?.[0])).toBe('https://misp.internal.example/attributes/restSearch');
    expect(JSON.parse(String(fetchMock.mock.calls[0]?.[1]?.body))).toMatchObject({ value: 'billing@invoices.example' });
    expect(r.events[0]).toMatchObject({ id: 'ev-uuid', name: 'Invoice lure campaign', org: 'Our SOC', reference: 'https://misp.internal.example/events/view/17' });
  });

  it('MalwareBazaar API lookup: signature and first-seen for a hash', async () => {
    const body = { query_status: 'ok', data: [{ sha256_hash: 'b'.repeat(64), signature: 'AgentTesla', first_seen: '2026-09-10 08:00:00', last_seen: null, file_name: 'invoice.exe', tags: ['exe'], delivery_method: 'email_attachment' }] };
    vi.stubGlobal('fetch', vi.fn(async () => respond(JSON.stringify(body))));
    const s = freshStore();
    const r = await connector('malwarebazaar-api')!.lookup!({ store: s, config: { ...cfg, abusechAuthKey: 'k' } }, 'sha256', 'b'.repeat(64));
    expect(r.hits[0]).toMatchObject({ family: 'AgentTesla', reference: `https://bazaar.abuse.ch/sample/${'b'.repeat(64)}/` });
    expect(r.hits[0]?.tags).toContain('delivery:email_attachment');
  });

  it('the HTTP client refuses hosts outside the connector allowlist (SSRF guard), even via redirects', async () => {
    await expect(fetchResource('https://169.254.169.254/latest/meta-data', { allowedHosts: ['urlhaus.abuse.ch'] })).rejects.toBeInstanceOf(HttpError);
    vi.stubGlobal('fetch', vi.fn(async () => new Response(null, { status: 302, headers: { location: 'http://127.0.0.1:8080/admin' } })));
    await expect(fetchResource('https://urlhaus.abuse.ch/downloads/csv/', { allowedHosts: ['urlhaus.abuse.ch'], retries: 0 })).rejects.toThrow(/refused/);
  });
});

describe('external event records', () => {
  it('recognises generated record series and generic indicator dumps', () => {
    expect(seriesKey('Phishing | Oct 13, 2026 | Part 182/566')).toBe(seriesKey('Phishing | Oct 12, 2026 | Part 182/566'));
    expect(seriesKey('Phishing | 2026-10-13 | Part 1 of 9')).toBe('phishing');
    expect(isGenericName('Phishing | Oct 13, 2026 | Part 182/566')).toBe(true);
    expect(isGenericName('Malware URLs daily feed 2026-10-01')).toBe(true);
    expect(isGenericName('Microsoft 365 AiTM phishing wave targeting finance')).toBe(false);
    expect(isGenericName('Tycoon2FA phishing kit')).toBe(false);
  });

  it('merges a series into one record and does not call a generic dump a reported campaign association', () => {
    const s = freshStore();
    s.ensureSource('otx', true);
    for (const d of [10, 11, 12]) s.upsertEvent('otx', { id: `p${d}`, name: `Phishing | Oct ${d}, 2026 | Part 3/9`, date: Date.UTC(2026, 9, d), updatedAt: null, org: 'feeds', tags: [], threatLevel: null, reference: null, indicators: [{ type: 'url', value: 'https://kit.example/o365/a1b2c3/login.php', category: null, toIds: true, comment: null }] });
    s.upsertEvent('otx', { id: 'named', name: 'Storm-0000 AiTM campaign against payroll teams', date: Date.UTC(2026, 9, 1), updatedAt: null, org: 'research', tags: [], threatLevel: null, reference: null, indicators: [{ type: 'url', value: 'https://kit.example/o365/a1b2c3/login.php', category: null, toIds: true, comment: null }] });
    const { campaigns } = externalMatches(s, [{ messageId: 'm1', type: 'url', value: 'https://kit.example/o365/a1b2c3/login.php', role: 'link', context: null }]);
    expect(campaigns).toHaveLength(2);
    const series = campaigns.find((c) => c.generic);
    expect(series?.name).toBe('Phishing (series of 3 records)');
    expect(series?.seriesEventIds?.sort()).toEqual(['p10', 'p11', 'p12']);
    expect(series?.assessment).toBe('possible-association');
    expect(series?.rationale.join(' ')).toMatch(/not a named campaign/);
    const named = campaigns.find((c) => !c.generic);
    expect(named?.assessment).toBe('reported-association');
  });
});
