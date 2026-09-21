import { describe, expect, it } from 'vitest';
import { writeFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { analyzeEmail } from '../src/analyze';
import { toStixBundle, toMarkdown, toIocCsv } from '../src/export';
import { FIXTURES } from './helpers/fixtures';

const qrStub = async (): Promise<string | null> => 'https://mfa-reenroll.hr-portal-docs.com/auth?u=victim';

describe('golden fixtures', () => {
  for (const fx of FIXTURES) {
    it(`${fx.name} → ${fx.expect}`, async () => {
      const eml = fx.eml();
      const r = await analyzeEmail(eml, { qrDecoder: qrStub, now: new Date('2026-09-21T16:00:00Z') });
      const ids = r.findings.map((f) => f.id);
      const summary = `${r.verdict} ${r.score} :: ${r.findings.map((f) => `${f.id}(${f.weight})`).join(', ')}`;
      expect(r.verdict, summary).toBe(fx.expect);
      for (const want of fx.mustInclude ?? []) expect(ids.some((id) => id.startsWith(want)), `${want} missing: ${summary}`).toBe(true);
      for (const nope of fx.mustExclude ?? []) expect(ids.some((id) => id.startsWith(nope)), `${nope} present: ${summary}`).toBe(false);
      expect(r.id).toMatch(/^[0-9a-f]{64}$/);
      expect(r.fingerprint.keys.length).toBeGreaterThan(0);
      if (process.env['WRITE_FIXTURES']) {
        const dir = join(process.cwd(), 'fixtures', 'eml');
        mkdirSync(dir, { recursive: true });
        writeFileSync(join(dir, `${fx.name}.eml`), eml, 'latin1');
      }
    });
  }

  it('reports the forensic details of the recruiter email', async () => {
    const fx = FIXTURES.find((f) => f.name === 'recruiter-brand-claim');
    const r = await analyzeEmail(fx!.eml());
    expect(r.route.originIp).toBe('103.197.16.155');
    expect(r.route.originHost).toBe('mail.cb1155.mlrctk.com');
    expect(r.esp).toMatchObject({ id: 'mailercloud', customerId: '26174', campaignId: '1634010' });
    expect(r.auth).toMatchObject({ source: 'trusted', dmarc: 'pass', spf: 'pass', dkim: 'pass' });
    expect(r.sender.impersonatedBrand).toBe('ltimindtree');
    expect(r.html.trackingPixels).toBe(1);
    expect(r.findings.some((f) => f.id === 'html.tracking')).toBe(true);
    expect(r.fingerprint.infra.espCampaign).toBe('mailercloud:26174:1634010');
    expect(r.fingerprint.urls.templates).toContain('talentsjobs.in/links/{tok}/{n}');
  });

  it('exports STIX, CSV and Markdown', async () => {
    const r = await analyzeEmail(FIXTURES.find((f) => f.name === 'paypal-lookalike-credential')!.eml());
    const stix = toStixBundle(r) as { type: string; objects: { type: string }[] };
    expect(stix.type).toBe('bundle');
    expect(stix.objects.some((o) => o.type === 'indicator')).toBe(true);
    expect(toIocCsv(r)).toContain('paypa1-secure.com');
    expect(toMarkdown(r)).toContain('Likely phishing');
  });

  it('survives garbage input', async () => {
    const r = await analyzeEmail('this is not an email at all');
    expect(['safe', 'caution', 'danger']).toContain(r.verdict);
    const r2 = await analyzeEmail(new Uint8Array(0));
    expect(r2.sizeBytes).toBe(0);
  });
});
