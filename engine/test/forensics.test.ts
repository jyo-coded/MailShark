// Engine 1.1 forensic capabilities: DKIM verification (RFC 8463 test vectors), injected
// authentication results, provider trace headers, IOC extraction, coverage and classification.
import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { analyzeEmail } from '../src/analyze';
import { canonBodyRelaxed, verifyDkim } from '../src/analyzers/dkim';
import { findingDoc } from '../src/catalog';
import { buildEml, gmailReceived } from './helpers/mime';
import { FIXTURES } from './helpers/fixtures';

// RFC 8463 Appendix A.3, verbatim (3-space RFC indent removed; continuation lines keep one space).
const RFC8463 = [
  'DKIM-Signature: v=1; a=ed25519-sha256; c=relaxed/relaxed;',
  ' d=football.example.com; i=@football.example.com;',
  ' q=dns/txt; s=brisbane; t=1528637909; h=from : to :',
  ' subject : date : message-id : from : subject : date;',
  ' bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=;',
  ' b=/gCrinpcQOoIfuHNQIbq4pgh9kyIK3AQUdt9OdqQehSwhEIug4D11Bus',
  ' Fa3bT3FY5OsU7ZbnKELq+eXdp1Q1Dw==',
  'DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;',
  ' d=football.example.com; i=@football.example.com;',
  ' q=dns/txt; s=test; t=1528637909; h=from : to : subject :',
  ' date : message-id : from : subject : date;',
  ' bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=;',
  ' b=F45dVWDfMbQDGHJFlXUNB2HKfbCeLRyhDXgFpEL8GwpsRe0IeIixNTe3',
  ' DhCVlUrSjV4BwcVcOF6+FF3Zo9Rpo1tFOeS9mPYQTnGdaSGsgeefOsk2Jz',
  ' dA+L10TeYt9BgDfQNZtKdN1WO//KgIqXP7OdEFE4LjFYNcUxZQ4FADY+8=',
  'From: Joe SixPack <joe@football.example.com>',
  'To: Suzie Q <suzie@shopping.example.net>',
  'Subject: Is dinner ready?',
  'Date: Fri, 11 Jul 2003 21:00:37 -0700 (PDT)',
  'Message-ID: <20030712040037.46341.5F8J@football.example.com>',
  '',
  'Hi.',
  '',
  'We lost the game.  Are you hungry yet?',
  '',
  'Joe.',
  '',
].join('\r\n');

const KEYS: Record<string, string> = {
  'brisbane._domainkey.football.example.com': 'v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=',
  'test._domainkey.football.example.com':
    'v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDkHlOQoBTzWRiGs5V6NpP3idY6Wk08a5qhdR6wy5bdOKb2jLQiY/J16JYi0Qvx/byYzCNb3W91y3FutACDfzwQ/BC/e/8uBsCR+yz1Lxj+PL6lHvqMKrM3rG4hstT5QjvHO9PzoxZyVYLzBfO2EeC3Ip3G+2kryOTIKT+l/K4w3QIDAQAB',
};
const resolveKey = async (selector: string, domain: string): Promise<string | null> => KEYS[`${selector}._domainkey.${domain}`] ?? null;

describe('DKIM verification (RFC 8463 Appendix A vectors)', () => {
  it('verifies both the Ed25519 and the RSA signature and their body hashes', async () => {
    const res = await verifyDkim({ raw: RFC8463, recipients: [], receivedAt: null, resolveKey });
    expect(res).toHaveLength(2);
    for (const r of res) {
      expect(r.bodyHash).toBe('pass');
      expect(r.signature).toBe('pass');
      expect(r.coversFrom).toBe(true);
      expect(r.fromOversigned).toBe(true); // h= lists "from" twice; the message has one From
    }
    expect(res.map((r) => r.algorithm).sort()).toEqual(['ed25519-sha256', 'rsa-sha256']);
    expect(res.find((r) => r.algorithm === 'rsa-sha256')?.keyBits).toBe(1024);
  });

  it('verifies the body hash offline without any key lookup', async () => {
    const res = await verifyDkim({ raw: RFC8463, recipients: [], receivedAt: null });
    expect(res.every((r) => r.bodyHash === 'pass' && r.signature === 'not-checked')).toBe(true);
  });

  it('tolerates LF-only line endings (evidence saved on Unix)', async () => {
    const res = await verifyDkim({ raw: RFC8463.replace(/\r\n/g, '\n'), recipients: [], receivedAt: null, resolveKey });
    expect(res.every((r) => r.bodyHash === 'pass' && r.signature === 'pass')).toBe(true);
  });

  it('detects a modified body and a modified signed header separately', async () => {
    const body = await verifyDkim({ raw: RFC8463.replace('We lost the game.', 'We won the game.'), recipients: [], receivedAt: null, resolveKey });
    expect(body.every((r) => r.bodyHash === 'fail')).toBe(true);
    const header = await verifyDkim({ raw: RFC8463.replace('Subject: Is dinner ready?', 'Subject: Is lunch ready?'), recipients: [], receivedAt: null, resolveKey });
    expect(header.every((r) => r.bodyHash === 'pass' && r.signature === 'fail')).toBe(true);
  });

  it('reports a missing or revoked key as unverifiable, never as a failure', async () => {
    const missing = await verifyDkim({ raw: RFC8463, recipients: [], receivedAt: null, resolveKey: async () => null });
    expect(missing.every((r) => r.signature === 'key-unavailable')).toBe(true);
    const revoked = await verifyDkim({ raw: RFC8463, recipients: [], receivedAt: null, resolveKey: async () => 'v=DKIM1; k=rsa; p=' });
    expect(revoked.every((r) => r.signature === 'key-revoked')).toBe(true);
  });

  it('flags content appended beyond the signed body length (l=)', async () => {
    const signedBody = 'Hello,\r\n\r\nPlease find the agenda attached.\r\n';
    const canon = canonBodyRelaxed(signedBody);
    const bh = createHash('sha256').update(Buffer.from(canon, 'latin1')).digest('base64');
    const msg = [
      `DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=bank.example; s=s1; l=${canon.length}; h=from:to:subject:date; bh=${bh}; b=AAAA`,
      'From: Bank <alerts@bank.example>',
      'To: victim@gmail.com',
      'Subject: Agenda',
      'Date: Mon, 21 Sep 2026 10:00:00 +0000',
      '',
      signedBody + '\r\nURGENT: verify your account at https://bank-example.verify-now.top/login\r\n',
    ].join('\r\n');
    const [r] = await verifyDkim({ raw: msg, recipients: [], receivedAt: null });
    expect(r?.bodyHash).toBe('pass');
    expect(r?.bodyBeyondLimit).toBe(true);
    const report = await analyzeEmail(msg);
    expect(report.findings.map((f) => f.id)).toContain('dkim.body-appended');
  });

  it('suspects replay when a valid signature predates delivery by years and does not name the recipient', async () => {
    const delivered = [
      'Delivered-To: victim@gmail.com',
      'Received: from mail.football.example.com (mail.football.example.com. [192.0.2.25]) by mx.google.com with ESMTPS id x1 for <victim@gmail.com>; Mon, 21 Sep 2026 08:49:05 -0700 (PDT)',
      'Authentication-Results: mx.google.com; dkim=pass header.i=@football.example.com header.s=test; spf=pass smtp.mailfrom=joe@football.example.com; dmarc=pass (p=REJECT) header.from=football.example.com',
      RFC8463,
    ].join('\r\n');
    const report = await analyzeEmail(delivered, { dkimKeyResolver: resolveKey });
    const replay = report.findings.find((f) => f.id === 'dkim.replay-suspected');
    expect(replay?.severity).toBe('high');
    expect(report.dkim?.[0]?.recipientInSignedHeaders).toBe(false);
  });

  it('marks an evidence copy that changed after the receiver verified it', async () => {
    const delivered = [
      'Delivered-To: suzie@shopping.example.net',
      'Received: from mail.football.example.com (mail.football.example.com. [192.0.2.25]) by mx.shopping.example.net with ESMTPS id x1 for <suzie@shopping.example.net>; Fri, 11 Jul 2003 21:00:40 -0700 (PDT)',
      'Authentication-Results: mx.shopping.example.net; dkim=pass header.d=football.example.com header.s=test; dmarc=pass header.from=football.example.com',
      RFC8463.replace('Are you hungry yet?', 'Pay the invoice today.'),
    ].join('\r\n');
    const report = await analyzeEmail(delivered);
    const f = report.findings.find((x) => x.id === 'dkim.modified-after-delivery');
    expect(f?.category).toBe('integrity');
    expect(f?.weight).toBe(0);
  });
});

describe('header forensics', () => {
  const lure = (extra: [string, string][], received?: [string, string][]): string =>
    buildEml({
      headers: [
        ...(received ??
          gmailReceived({ ip: '45.133.1.77', host: 'vps77.hostingcheap.ru', auth: 'spf=softfail smtp.mailfrom=service@paypa1-secure.com; dmarc=fail (p=NONE) header.from=paypa1-secure.com' })),
        ...extra,
        ['From', '"PayPal" <service@paypa1-secure.com>'],
        ['To', 'victim@gmail.com'],
        ['Subject', 'Your account is limited'],
        ['Date', 'Mon, 21 Sep 2026 15:48:59 +0000'],
        ['Message-ID', '<1@paypa1-secure.com>'],
      ],
      text: 'Dear customer, verify your account at https://paypa1-secure.com/login today.',
    });

  it('detects an Authentication-Results header injected below the receiver’s own', async () => {
    const r = await analyzeEmail(lure([['Authentication-Results', 'mx.google.com; spf=pass smtp.mailfrom=paypal.com; dkim=pass header.d=paypal.com; dmarc=pass header.from=paypal.com']]));
    expect(r.forensics?.injectedAuthResults).toHaveLength(1);
    expect(r.findings.map((f) => f.id)).toContain('auth.injected-results');
    expect(r.auth.dmarc).toBe('fail'); // the receiver's verdict is still the one used
  });

  it('detects verdicts claiming a provider that never handled the message', async () => {
    const received: [string, string][] = [
      ['Received', 'from mail.attacker.example (mail.attacker.example [203.0.113.9]) by mx.corp.example with ESMTP id 1; Mon, 21 Sep 2026 15:49:00 +0000'],
    ];
    const r = await analyzeEmail(lure([['Authentication-Results', 'mx.google.com; dkim=pass header.d=paypal.com; dmarc=pass header.from=paypal.com']], received));
    expect(r.forensics?.injectedAuthResults[0]?.reason).toMatch(/no server of that provider/);
  });

  it('detects a HELO that impersonates a brand but resolves elsewhere', async () => {
    const received: [string, string][] = [
      ['Delivered-To', 'victim@gmail.com'],
      ['Received', 'from mail.paypal.com (vps77.hostingcheap.ru. [45.133.1.77]) by mx.google.com with ESMTPS id 1 for <victim@gmail.com>; Mon, 21 Sep 2026 15:49:00 +0000'],
      ['Authentication-Results', 'mx.google.com; spf=softfail smtp.mailfrom=service@paypa1-secure.com; dmarc=fail header.from=paypa1-secure.com'],
    ];
    const r = await analyzeEmail(lure([], received));
    expect(r.forensics?.heloMismatch).toMatchObject({ helo: 'mail.paypal.com', rdns: 'vps77.hostingcheap.ru', verified: true });
    expect(r.findings.find((f) => f.id === 'route.helo-impersonation')?.severity).toBe('medium');
  });

  it('extracts provider trace headers: client IP, authenticated account, sending script', async () => {
    const r = await analyzeEmail(
      lure([
        ['X-PHP-Script', 'shop-example.com/wp-content/uploads/mailer.php for 198.51.100.23'],
        ['X-Authenticated-Sender', 'srv12.host.example: info@shop-example.com'],
        ['X-AntiAbuse', 'Primary Hostname - srv12.host.example'],
      ]),
    );
    expect(r.forensics?.originating).toMatchObject({ clientIp: '198.51.100.23', authenticatedSender: 'info@shop-example.com', hostingServer: 'srv12.host.example' });
    const ids = r.findings.map((f) => f.id);
    expect(ids).toEqual(expect.arrayContaining(['route.authenticated-sender-mismatch', 'route.script-sender', 'route.originating-client']));
    expect(r.iocs?.some((i) => i.role === 'client-ip' && i.value === '198.51.100.23')).toBe(true);
  });

  it('does not trust a "dmarc=pass" that cannot be attributed to the receiver', async () => {
    // No Received chain: the only Authentication-Results header could have been written by anyone.
    const eml = buildEml({
      headers: [
        ['Authentication-Results', 'mx.example; dkim=pass header.d=paypal.com; spf=pass smtp.mailfrom=paypal.com; dmarc=pass header.from=paypal.com'],
        ['From', 'PayPal <service@paypal.com>'],
        ['To', 'victim@example.org'],
        ['Subject', 'Receipt for your payment'],
        ['Date', 'Mon, 21 Sep 2026 15:48:59 +0000'],
        ['Message-ID', '<1@paypal.com>'],
      ],
      text: 'You sent a payment of $24.99 to Example Store. View the details in your PayPal account.',
    });
    const r = await analyzeEmail(eml);
    expect(r.auth.source).toBe('topmost');
    expect(r.sender.verifiedBrand).toBeNull();
    expect(r.findings.map((f) => f.id)).toContain('auth.unverified-results');
    expect(r.findings.find((f) => f.id === 'auth.dmarc-pass')?.weight ?? 0).toBeGreaterThan(-0.3);
  });
});

describe('indicators, coverage and classification', () => {
  const fixture = (name: string): string => (FIXTURES.find((f) => f.name === name) as (typeof FIXTURES)[number]).eml();

  it('extracts typed indicators with roles and component references', async () => {
    const r = await analyzeEmail(fixture('paypal-lookalike-credential'));
    const iocs = r.iocs ?? [];
    expect(iocs).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ type: 'email', value: 'service@paypa1-secure.com', role: 'from', ref: 'header:From' }),
        expect.objectContaining({ type: 'ipv4', value: '45.133.1.77', role: 'origin-ip' }),
        expect.objectContaining({ type: 'url', role: 'link', suspicious: true }),
        expect.objectContaining({ type: 'domain', value: 'paypa1-secure.com', role: 'link-domain' }),
      ]),
    );
    for (const ioc of iocs) expect(ioc.ref).toMatch(/^(header:|link\[|attachment\[|body)/);
  });

  it('records attachment hashes and archive entries as indicators', async () => {
    const r = await analyzeEmail(fixture('macro-invoice'));
    const iocs = r.iocs ?? [];
    expect(iocs.filter((i) => i.type === 'sha256' && i.role === 'attachment').length).toBeGreaterThan(0);
    expect(iocs.some((i) => i.type === 'filename' && i.role === 'attachment-name')).toBe(true);
  });

  it('classifies the golden fixtures consistently with their verdicts', async () => {
    for (const fx of FIXTURES) {
      const r = await analyzeEmail(fx.eml());
      const cls = r.classification?.class;
      if (fx.expect === 'danger') expect(cls, fx.name).toBe('malicious');
      if (fx.expect === 'safe') expect(['benign', 'inconclusive'], fx.name).toContain(cls);
      if (fx.expect === 'caution') expect(['suspicious', 'malicious'], fx.name).toContain(cls);
    }
  });

  it('calls a message without evidence inconclusive rather than benign', async () => {
    const r = await analyzeEmail('From: someone@example.org\r\nSubject: hi\r\n\r\n');
    expect(r.coverage?.score).toBeLessThan(0.5);
    expect(r.classification?.class).toBe('inconclusive');
    expect(r.classification?.confidence).toBe('low');
    const auth = r.coverage?.layers.find((l) => l.id === 'authentication');
    expect(auth?.status).toBe('absent');
    expect(auth?.note).toMatch(/not a failure/);
  });

  it('finds cryptocurrency wallets in extortion lures', async () => {
    const eml = buildEml({
      headers: [['From', 'x <x@example.net>'], ['To', 'v@example.org'], ['Subject', 'I recorded you'], ['Date', 'Mon, 21 Sep 2026 10:00:00 +0000'], ['Message-ID', '<w@example.net>']],
      text: 'I have recorded you through your webcam. Pay $1500 in bitcoin to bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh within 48 hours or I will send the video to all your contacts.',
    });
    const r = await analyzeEmail(eml);
    expect(r.content.wallets).toContain('bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh');
    expect(r.iocs?.some((i) => i.type === 'btc')).toBe(true);
  });

  it('documents every finding the fixtures produce', async () => {
    for (const fx of FIXTURES) {
      const r = await analyzeEmail(fx.eml());
      for (const f of r.findings) expect(findingDoc(f.id), f.id).not.toBeNull();
    }
  });
});
