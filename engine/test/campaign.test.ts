import { describe, expect, it } from 'vitest';
import { analyzeEmail } from '../src/analyze';
import { similarity } from '../src/campaign/similarity';
import { assignCampaign, profileCampaign, type CampaignMember } from '../src/campaign/cluster';
import { BloomFilter, BloomIntel, BLOOM_SEED_1, BLOOM_SEED_2, hostCandidates } from '../src/intel/bloom';
import { murmur3 } from '../src/util/hash';
import { buildEml, gmailReceived } from './helpers/mime';

/** One phishing template, rotated across sender, domain, IP and URL (the adversarial scenario). */
function variant(i: number): string {
  const domains = ['secure-docs-portal.com', 'docs-review-center.net', 'fileshare-verify.org', 'doc-access-hub.info'];
  const d = domains[i % domains.length] as string;
  const ip = `185.${100 + i}.${20 + i}.${7 + i}`;
  return buildEml({
    headers: [
      ...gmailReceived({ ip, host: `mail${i}.${d}`, auth: `spf=pass smtp.mailfrom=noreply@${d}; dmarc=pass (p=NONE) header.from=${d}` }),
      ['From', `SharePoint Online <noreply@${d}>`],
      ['To', `employee${i}@corp.example`],
      ['Subject', `Employee${i} shared "Q${(i % 4) + 1} Salary Adjustment ${2026 + (i % 2)}.pdf" with you`],
      ['Date', `Mon, ${10 + i} Sep 2026 0${i % 9}:15:00 +0000`],
      ['Message-ID', `<${1000 + i}.${i * 7919}@${d}>`],
      ['X-Mailer', 'Microsoft Outlook 16.0'],
    ],
    html: `<table class="ms-card"><tr><td class="hdr"><img src="https://cdn.${d}/logo.png"></td></tr><tr><td class="body"><p>Employee${i} has shared a document with you.</p><p>Q${(i % 4) + 1} Salary Adjustment. Please review document and sign in with your corporate credentials to view the file before it expires today.</p><p><a class="btn" href="https://view.${d}/s/${(i * 2654435761).toString(36)}x9k2/open">Open document</a></p></td></tr></table>`,
  });
}

function unrelated(): string {
  return buildEml({
    headers: [
      ...gmailReceived({ ip: '209.85.220.41', host: 'mail-sor-f41.google.com', auth: 'dkim=pass header.i=@gmail.com; spf=pass smtp.mailfrom=friend@gmail.com; dmarc=pass header.from=gmail.com' }),
      ['From', 'Asha <asha.k@gmail.com>'],
      ['To', 'me@gmail.com'],
      ['Subject', 'Trip photos!'],
      ['Date', 'Sat, 19 Sep 2026 10:00:00 +0000'],
      ['Message-ID', '<CAabc@mail.gmail.com>'],
    ],
    text: 'Hey! Finally uploaded the pictures from Coorg. The waterfall ones came out great, let me know which ones you want printed.',
  });
}

describe('campaign correlation under indicator rotation', () => {
  it('links rotated variants and keeps unrelated mail apart', async () => {
    if (process.env['WRITE_FIXTURES']) {
      const { mkdirSync, writeFileSync } = await import('node:fs');
      mkdirSync('fixtures/eml', { recursive: true });
      for (const i of [0, 1, 2, 3]) writeFileSync(`fixtures/eml/campaign-sharepoint-${i + 1}.eml`, variant(i), 'latin1');
    }
    const reports = await Promise.all([0, 1, 2, 3].map((i) => analyzeEmail(variant(i))));
    const other = await analyzeEmail(unrelated());
    const fps = reports.map((r) => r.fingerprint);
    // Every indicator differs…
    expect(new Set(fps.map((f) => f.sender.fromOrg)).size).toBe(4);
    expect(new Set(fps.map((f) => f.infra.originIp)).size).toBe(4);
    // …yet the campaign is recognised.
    for (let i = 1; i < fps.length; i++) expect(similarity(fps[0]!, fps[i]!).score).toBeGreaterThanOrEqual(0.6);
    expect(similarity(fps[0]!, other.fingerprint).score).toBeLessThan(0.35);

    const members: CampaignMember[] = [];
    let cid: string | null = null;
    for (const [i, r] of reports.entries()) {
      const a = assignCampaign(r.fingerprint, members, r.id);
      if (i === 0) expect(a.clusterId).toBeNull();
      else expect(a.clusterId).toBe('C-TEST');
      cid = a.clusterId ?? 'C-TEST';
      members.push({ id: r.id, clusterId: cid, fp: r.fingerprint, score: r.score, verdict: r.verdict });
    }
    expect(assignCampaign(other.fingerprint, members, other.id).clusterId).toBeNull();

    const profile = profileCampaign(fps);
    const inv = profile.invariants.map((x) => x.attr);
    const rot = profile.rotated.map((x) => x.attr);
    expect(inv).toEqual(expect.arrayContaining(['displayName', 'skeleton', 'xMailer']));
    expect(rot).toEqual(expect.arrayContaining(['fromOrg', 'originNet']));
    expect(profile.attackerCost).toBeGreaterThanOrEqual(3);
  });
});

describe('bloom filter threat feed', () => {
  it('matches hosts and parents without false negatives', () => {
    const entries = ['evil-login.example', 'phish.badsite.top', 'x.web.app'];
    const m = 4096;
    const k = 7;
    const bits = new Uint8Array(m / 8);
    for (const e of entries) {
      const h1 = murmur3(e, BLOOM_SEED_1);
      const h2 = (murmur3(e, BLOOM_SEED_2) | 1) >>> 0;
      for (let i = 0; i < k; i++) {
        const idx = (h1 + i * h2) % m;
        bits[idx >>> 3] = (bits[idx >>> 3] as number) | (1 << (idx & 7));
      }
    }
    const intel = new BloomIntel([new BloomFilter({ name: 'test', m, k, count: entries.length }, bits)]);
    expect(intel.lookupDomain('evil-login.example')).toBe('test');
    expect(intel.lookupDomain('www.evil-login.example')).toBe('test');
    expect(intel.lookupDomain('a.b.phish.badsite.top')).toBe('test');
    expect(intel.lookupDomain('x.web.app')).toBe('test');
    expect(intel.lookupDomain('google.com')).toBeNull();
    expect(hostCandidates('a.b.example.co.uk')).toEqual(['a.b.example.co.uk', 'b.example.co.uk', 'example.co.uk']);
  });
});
