import { describe, expect, it } from 'vitest';
import { domainToUnicode } from 'node:url';
import { createHash } from 'node:crypto';
import { md5Hex, murmur3, minhash, minhashSimilarity, shingles, simhash, simhashSimilarity, sha256Hex } from '../src/util/hash';
import { hostInfo, ipNetwork, isPublicIp, punycodeDecodeLabel, toUnicodeHost } from '../src/util/domain';
import { levenshtein, templatize, tokenize, hasMixedScriptWord } from '../src/util/text';
import { parseReceived, analyzeRoute } from '../src/analyzers/route';
import { analyzeAuth, parseAuthResults, parseDkimSignature } from '../src/analyzers/auth';
import { detectLookalike, skeleton } from '../src/analyzers/lookalike';
import { analyzeLinks, extractTextUrls, unwrapUrl, urlTemplate } from '../src/analyzers/links';
import { analyzeHtml } from '../src/analyzers/html';
import { analyzeContent } from '../src/analyzers/content';
import { listZip, sniff, analyzeAttachment } from '../src/analyzers/attachments';
import { parseHeaderBlock, parseParams, walkMime } from '../src/mime/raw';
import { findBrands } from '../src/data/brands';
import { zipSync } from 'fflate';

const enc = (s: string): Uint8Array => new TextEncoder().encode(s);

describe('hashing', () => {
  it('md5 matches RFC 1321 vectors', () => {
    expect(md5Hex(enc(''))).toBe('d41d8cd98f00b204e9800998ecf8427e');
    expect(md5Hex(enc('abc'))).toBe('900150983cd24fb0d6963f7d28e17f72');
    expect(md5Hex(enc('The quick brown fox jumps over the lazy dog'))).toBe('9e107d9d372bb6826bd81d3542a419d6');
    for (const len of [55, 56, 63, 64, 65, 1000, 4097]) {
      const data = new Uint8Array(len).map((_, i) => (i * 31 + 7) & 0xff);
      expect(md5Hex(data), `len ${len}`).toBe(createHash('md5').update(data).digest('hex'));
    }
  });
  it('sha256 uses WebCrypto', async () => {
    expect(await sha256Hex(enc('abc'))).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  });
  it('murmur3 x86_32 matches reference vectors', () => {
    expect(murmur3('', 0)).toBe(0);
    expect(murmur3('hello', 0)).toBe(613153351);
    expect(murmur3('The quick brown fox jumps over the lazy dog', 0)).toBe(0x2e4ff723);
    expect(murmur3('', 1)).toBe(0x514e28b7);
  });
  it('minhash approximates Jaccard similarity', () => {
    const a = shingles(tokenize('your account has been suspended please verify your identity within 24 hours to restore access'));
    const b = shingles(tokenize('your account has been suspended please verify your identity within 48 hours to restore access'));
    const c = shingles(tokenize('lunch on friday? the new ramen place near the office looks great'));
    expect(minhashSimilarity(minhash(a), minhash(b))).toBeGreaterThan(0.45);
    expect(minhashSimilarity(minhash(a), minhash(c))).toBeLessThan(0.1);
    expect(simhashSimilarity(simhash(a), simhash(b))).toBeGreaterThan(simhashSimilarity(simhash(a), simhash(c)));
  });
});

describe('domains & text', () => {
  it('decodes punycode like the platform does', () => {
    for (const host of ['xn--pypal-4ve.com', 'xn--80ak6aa92e.com', 'xn--mnchen-3ya.de']) {
      expect(toUnicodeHost(host)).toBe(domainToUnicode(host));
    }
    expect(punycodeDecodeLabel('mnchen-3ya')).toBe('münchen');
  });
  it('finds registrable domains via the PSL', () => {
    expect(hostInfo('a.b.example.co.uk').regDomain).toBe('example.co.uk');
    expect(hostInfo('mail.cb1155.mlrctk.com').regDomain).toBe('mlrctk.com');
    expect(hostInfo('103.197.16.155').isIp).toBe(true);
  });
  it('classifies IPs', () => {
    expect(isPublicIp('10.1.2.3')).toBe(false);
    expect(isPublicIp('192.168.0.1')).toBe(false);
    expect(isPublicIp('103.197.16.155')).toBe(true);
    expect(isPublicIp('2002:a05:612c::1')).toBe(true);
    expect(isPublicIp('fe80::1')).toBe(false);
    expect(ipNetwork('103.197.16.155')).toBe('103.197.16.0/24');
    expect(ipNetwork('2002:a05:612c:2c92::1')).toBe('2002:0a05:612c::/48');
  });
  it('templatizes volatile values', () => {
    expect(templatize('Invoice #INV-20931 due 21/09/2026 for john@x.com')).toBe('invoice #inv-{n} due {date} for {email}');
    expect(levenshtein('paypal', 'paypa1')).toBe(1);
    expect(hasMixedScriptWord('pаypal')).toBe(true);
    expect(hasMixedScriptWord('paypal login')).toBe(false);
  });
});

describe('MIME', () => {
  it('parses folded headers and params', () => {
    const { headers } = parseHeaderBlock('Subject: hello\r\n world\r\nX-Test: 1\r\nContent-Type: multipart/mixed;\r\n boundary="abc"');
    expect(headers[0]).toMatchObject({ key: 'subject', value: 'hello world' });
    const p = parseParams('multipart/mixed; boundary="abc"; charset=utf-8');
    expect(p.value).toBe('multipart/mixed');
    expect(p.params).toEqual({ boundary: 'abc', charset: 'utf-8' });
    expect(parseParams(`attachment; filename*=UTF-8''r%C3%A9sum%C3%A9.pdf`).params['filename']).toBe('résumé.pdf');
  });
  it('walks the MIME tree and flags anomalies', () => {
    const raw = 'Content-Type: multipart/mixed; boundary="b1"\r\n\r\n--b1\r\nContent-Type: text/plain\r\n\r\nhi\r\n--b1\r\nContent-Type: application/pdf; name="x.pdf"\r\n\r\n%PDF\r\n';
    const w = walkMime(raw);
    expect(w.parts.map((p) => p.contentType)).toEqual(['multipart/mixed', 'text/plain', 'application/pdf']);
    expect(w.anomalies).toContain('unterminated-multipart');
  });
});

describe('route', () => {
  const gmail = [
    'by 2002:a05:612c:2c92:b0:605:d55e:8f60 with SMTP id iu18csp12415996vqb; Mon, 21 Sep 2026 08:49:05 -0700 (PDT)',
    'from mail.cb1155.mlrctk.com (mail.cb1155.mlrctk.com. [103.197.16.155]) by mx.google.com with ESMTPS id 6a1803df08f44-912 for <x@gmail.com> (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256); Mon, 21 Sep 2026 08:49:04 -0700 (PDT)',
    'from [10.0.0.5] (unknown [203.0.113.99]) by relay.attacker.example (Postfix) with ESMTPSA id AAA; Mon, 21 Sep 2026 15:40:00 +0000',
  ];
  it('parses a received line', () => {
    const hop = parseReceived(gmail[1] as string, 1);
    expect(hop).toMatchObject({ fromHost: 'mail.cb1155.mlrctk.com', fromRdns: 'mail.cb1155.mlrctk.com', fromIp: '103.197.16.155', byHost: 'mx.google.com', protocol: 'ESMTPS' });
    expect(hop.tls).toBe('TLS1_2');
  });
  it('finds the hand-off hop and distrusts forged lower hops', () => {
    const r = analyzeRoute(gmail, 'Mon, 21 Sep 2026 15:48:59 +0000');
    expect(r.receiverOrg).toBe('google.com');
    expect(r.originIp).toBe('103.197.16.155');
    expect(r.originHost).toBe('mail.cb1155.mlrctk.com');
    const byIndex = new Map(r.hops.map((h) => [h.index, h]));
    expect(byIndex.get(0)?.trusted).toBe(true);
    expect(byIndex.get(1)?.trusted).toBe(true);
    expect(byIndex.get(2)?.trusted).toBe(false);
    expect(r.hops[0]?.index).toBe(2); // oldest first
  });
});

describe('authentication', () => {
  it('parses Gmail Authentication-Results', () => {
    const p = parseAuthResults('mx.google.com; dkim=pass header.i=@hiring.talentsjobs.in header.s=mc header.b=abc; spf=pass (google.com: domain of b@mlrctk.com designates 1.2.3.4 as permitted sender) smtp.mailfrom=b@mlrctk.com; dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=hiring.talentsjobs.in');
    expect(p.authServId).toBe('mx.google.com');
    expect(p.results.map((r) => `${r.method}=${r.result}`)).toEqual(['dkim=pass', 'spf=pass', 'dmarc=pass']);
    expect(p.results[2]?.props['header.from']).toBe('hiring.talentsjobs.in');
  });
  it('prefers the receiver-written header over attacker-injected ones', () => {
    const a = analyzeAuth({
      authResults: ['mx.google.com; spf=fail smtp.mailfrom=alerts@chase.com; dmarc=fail (p=REJECT) header.from=chase.com', 'evil.example; dkim=pass header.d=chase.com; dmarc=pass header.from=chase.com'],
      arcAuthResults: [],
      receivedSpf: [],
      dkimSignatures: [],
      receiverOrg: 'google.com',
      fromDomain: 'chase.com',
    });
    expect(a.source).toBe('trusted');
    expect(a.dmarc).toBe('fail');
    expect(a.dmarcPolicy).toBe('reject');
  });
  it('handles Exchange Online headers without authserv-id', () => {
    const a = analyzeAuth({
      authResults: ['spf=pass (sender IP is 1.2.3.4) smtp.mailfrom=contoso.com; dkim=pass (signature was verified) header.d=contoso.com;dmarc=pass action=none header.from=contoso.com;compauth=pass reason=100'],
      arcAuthResults: [],
      receivedSpf: [],
      dkimSignatures: ['v=1; a=rsa-sha256; d=contoso.com; s=selector1; h=From:To:Subject; bh=x; b=y'],
      receiverOrg: 'outlook.com',
      fromDomain: 'contoso.com',
    });
    expect(a.source).toBe('trusted');
    expect(a.compauth).toBe('pass');
    expect(a.dkimAligned).toBe(true);
    expect(a.signatures[0]).toMatchObject({ domain: 'contoso.com', selector: 'selector1', signedHeaders: ['from', 'to', 'subject'] });
  });
  it('parses DKIM signatures', () => {
    expect(parseDkimSignature('v=1; d=Example.COM; s=s1; a=rsa-sha256; h=from : to')).toMatchObject({ domain: 'example.com', signedHeaders: ['from', 'to'] });
  });
});

describe('lookalikes', () => {
  it('catches homoglyphs, typos, embedding and subdomain abuse', () => {
    expect(detectLookalike('paypa1.com')?.kind).toBe('homoglyph');
    expect(detectLookalike('rnicrosoft.com')?.brand.id).toBe('microsoft');
    expect(detectLookalike('xn--pypal-4ve.com')?.brand.id).toBe('paypal');
    expect(detectLookalike('amazom.com')?.kind).toBe('typosquat');
    expect(detectLookalike('paypal-secure-login.com')?.kind).toBe('embedded');
    expect(detectLookalike('paypal.com.account-review.ru')?.kind).toBe('subdomain');
  });
  it('does not flag real brands or unrelated words', () => {
    for (const d of ['paypal.com', 'www.amazon.in', 'accounts.google.com', 'tomato.com', 'example.com', 'mlrctk.com', 'github.com', 'login.microsoftonline.com']) {
      expect(detectLookalike(d), d).toBeNull();
    }
    expect(skeleton('rnicrosoft')).toBe(skeleton('microsoft'));
  });
});

describe('brands', () => {
  it('requires context for ambiguous brands in body text', () => {
    expect(findBrands('I ate an apple today', false).map((b) => b.id)).not.toContain('apple');
    expect(findBrands('Your Apple ID has been locked', false).map((b) => b.id)).toContain('apple');
    expect(findBrands('Apple', true).map((b) => b.id)).toContain('apple');
    expect(findBrands('An economic outlook for 2027', false).map((b) => b.id)).not.toContain('microsoft');
  });
});

describe('links', () => {
  it('extracts and unwraps URLs', () => {
    expect(extractTextUrls('see https://example.com/a?b=1, and www.test.org.')).toEqual(['https://example.com/a?b=1', 'http://www.test.org']);
    expect(unwrapUrl('https://www.google.com/url?q=https://evil.example/x&sa=D').url).toBe('https://evil.example/x');
    expect(unwrapUrl('https://nam12.safelinks.protection.outlook.com/?url=https%3A%2F%2Fevil.example%2Fy&data=1').url).toBe('https://evil.example/y');
  });
  it('templates per-recipient tokens away', () => {
    const t = urlTemplate(new URL('https://hiring.talentsjobs.in/links/cWbxEMSfsbsMkgUeaZMBwDeaBaqCaFWMVXhcaMDaea/4101188'), 'talentsjobs.in');
    expect(t).toBe('talentsjobs.in/links/{tok}/{n}');
  });
  it('flags deceptive links', () => {
    const [l] = analyzeLinks([{ url: 'https://paypa1-secure.com/login', source: 'html-anchor', text: 'https://www.paypal.com/signin' }], null, new Set());
    expect(l?.flags).toContain('text-href-mismatch');
    expect(l?.risk).toBe(3);
    const [ip] = analyzeLinks([{ url: 'http://45.133.1.80/chase/verify.php', source: 'html-anchor', text: 'Verify now' }], null, new Set());
    expect(ip?.flags).toContain('ip-host');
    const [esp] = analyzeLinks([{ url: 'https://u1.ct.sendgrid.net/ls/click?upn=abc', source: 'html-anchor', text: 'www.example-weekly.com' }], null, new Set());
    expect(esp?.flags).toContain('text-href-mismatch-tracking');
    expect(esp?.risk).toBe(0);
  });
  it('consults the threat-intel provider', () => {
    const intel = { lookupDomain: (d: string) => (d === 'bad.example' ? 'test-feed' : null) };
    const [l] = analyzeLinks([{ url: 'https://login.bad.example/x', source: 'text' }], { lookupDomain: (d) => (d.endsWith('bad.example') ? intel.lookupDomain('bad.example') : null) }, new Set());
    expect(l?.intelHit).toBe('test-feed');
  });
});

describe('html', () => {
  it('extracts visible vs hidden text, forms and pixels', () => {
    const r = analyzeHtml('<div style="display:none">free viagra hidden salt text</div><p>Hello <b>there</b></p><form action="https://x.example/p"><input type="password" name="pw"></form><img src="https://t.example/o.gif" width="1" height="1"><a href="https://a.example">Go</a>');
    expect(r.visibleText).toContain('Hello there');
    expect(r.visibleText).not.toContain('viagra');
    expect(r.hiddenText).toContain('viagra');
    expect(r.analysis.forms[0]?.hasPassword).toBe(true);
    expect(r.analysis.trackingPixels).toBe(1);
    expect(r.links.find((l) => l.source === 'html-anchor')).toMatchObject({ url: 'https://a.example', text: 'Go' });
  });
});

describe('content', () => {
  it('recognizes credential phishing with urgency', () => {
    const c = analyzeContent({ subject: 'Action required: verify your account', text: 'Dear Customer, your account will be suspended within 24 hours unless you verify your identity. Click here to verify.', inReplyTo: null, references: null, hasLinks: true, hasAttachments: false });
    expect(c.intent).toBe('credential');
    expect(c.urgency).toBeGreaterThanOrEqual(2);
    expect(c.genericGreeting).toBe(true);
    expect(c.requestedActions).toContain('click a link');
  });
  it('flags fake replies only without threading headers', () => {
    expect(analyzeContent({ subject: 'RE: invoice', text: 'see attached', inReplyTo: null, references: null, hasLinks: false, hasAttachments: false }).fakeReply).toBe(true);
    expect(analyzeContent({ subject: 'RE: invoice', text: 'see attached', inReplyTo: '<a@b>', references: null, hasLinks: false, hasAttachments: false }).fakeReply).toBe(false);
  });
  it('stays quiet on ordinary mail', () => {
    const c = analyzeContent({ subject: 'Lunch friday?', text: 'Hey, want to grab ramen near the office on Friday around 1?', inReplyTo: null, references: null, hasLinks: false, hasAttachments: false });
    expect(c.intent).toBeNull();
    expect(c.urgency).toBe(0);
  });
});

describe('attachments', () => {
  it('sniffs real types', () => {
    expect(sniff(enc('%PDF-1.7\n'))).toBe('pdf');
    expect(sniff(new Uint8Array([0x4d, 0x5a, 0x90, 0]))).toBe('pe');
    expect(sniff(enc('<!DOCTYPE html><html>'))).toBe('html');
    expect(sniff(enc('<?xml version="1.0"?><svg xmlns="x">'))).toBe('svg');
  });
  it('lists zip entries and detects encryption + executables', async () => {
    const z = zipSync({ 'invoice.pdf.exe': new Uint8Array([0x4d, 0x5a, 1, 2]), 'readme.txt': enc('hi') });
    expect(listZip(z)?.map((e) => e.name).sort()).toEqual(['invoice.pdf.exe', 'readme.txt']);
    const a = await analyzeAttachment({ filename: 'invoice.zip', mimeType: 'application/zip', disposition: 'attachment', content: z }, null, 1e7);
    expect(a.flags).toContain('archive-executable');
    expect(a.risk).toBe(3);
  });
  it('catches double extensions and type mismatches', async () => {
    const a = await analyzeAttachment({ filename: 'scan.pdf.exe', mimeType: 'application/pdf', disposition: 'attachment', content: new Uint8Array([0x4d, 0x5a, 0, 0]) }, null, 1e7);
    expect(a.flags).toEqual(expect.arrayContaining(['double-extension', 'executable']));
    const b = await analyzeAttachment({ filename: 'report.pdf', mimeType: 'application/pdf', disposition: 'attachment', content: enc('<html><body>hi</body></html>') }, null, 1e7);
    expect(b.flags).toContain('type-mismatch');
  });
  it('inspects PDFs for scripts and links', async () => {
    const pdf = enc('%PDF-1.4\n1 0 obj << /Type /Catalog /OpenAction 2 0 R >> endobj\n2 0 obj << /S /JavaScript /JS (app.alert(1)) >> endobj\n3 0 obj << /Type /Page /Annots [<< /A << /S /URI /URI (https://evil.example/login) >> >>] >> endobj');
    const a = await analyzeAttachment({ filename: 'doc.pdf', mimeType: 'application/pdf', disposition: 'attachment', content: pdf }, null, 1e7);
    expect(a.flags).toEqual(expect.arrayContaining(['pdf-javascript', 'pdf-openaction', 'pdf-autorun-script']));
    expect(a.urls).toContain('https://evil.example/login');
  });
});
