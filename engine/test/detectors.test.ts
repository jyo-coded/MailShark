// Detectors added from the real-corpus evaluation (Nazario / phishing_pot / SpamAssassin).
import { describe, expect, it } from 'vitest';
import { analyzeEmail } from '../src/analyze';
import { findBrandsInName, findBrandsCollapsed } from '../src/data/brands';
import { analyzeContent } from '../src/analyzers/content';
import { deobfuscate } from '../src/util/text';
import { buildEml } from './helpers/mime';

const base = (h: [string, string][], text: string, html?: string): string =>
  buildEml({ headers: [['Date', 'Mon, 21 Sep 2026 10:00:00 +0000'], ['Message-ID', '<x1@example.net>'], ...h], text, ...(html ? { html } : {}) });

const ids = async (eml: string): Promise<string[]> => (await analyzeEmail(eml)).findings.map((f) => f.id);

describe('brand matching in display names', () => {
  it('sees through punctuation, spacing, homoglyphs and invisible characters', () => {
    const names = (s: string): string[] => findBrandsInName(s).map((b) => b.id);
    expect(names('American .Express')).toContain('amex');
    expect(names('Geek<>Squad® Support-Team')).toContain('geeksquad');
    expect(names('AppStore')).toContain('apple');
    expect(names('NeIflíx')).toContain('netflix');
    expect(names('Ꮇ\u{E0139}\u{E0139}icrosof\u{E0139}t Bill Teams')).toContain('microsoft');
  });
  it('does not treat surnames as brand claims', () => {
    expect(findBrandsInName('Edward Norton').map((b) => b.id)).not.toContain('norton');
    expect(findBrandsInName('Norton Support').map((b) => b.id)).toContain('norton');
  });
  it('finds brands in split-word text', () => {
    expect(findBrandsCollapsed('Lin ked i n Busi ne ss Invi tat ion').map((b) => b.id)).toContain('linkedin');
    expect(deobfuscate('𝐏𝐋𝐄𝐀𝐒𝐄')).toBe('PLEASE');
  });
});

describe('sender & content detectors', () => {
  it('flags an outsider posing as the recipient’s own organisation', async () => {
    const found = await ids(base([['From', 'monkey.org Email Admin <office@newspread-ie.com>'], ['To', 'jose@monkey.org'], ['Subject', 'Account Password Expiry']], 'Your password expiry is today. Keep the same password by validating now.'));
    expect(found).toContain('sender.recipient-org-lure');
  });
  it('flags IT-role display names on credential lures', async () => {
    const found = await ids(base([['From', 'Email Account Administrator <sea@wikasa.co.id>'], ['To', 'me@example.org'], ['Subject', 'Dear User']], 'Your mailbox is full. Re-validate your e-mail password to avoid losing incoming messages.'));
    expect(found).toContain('sender.role-name');
  });
  it('treats a phone number in the subject of a payment notice as a call-back scam', async () => {
    const r = await analyzeEmail(base([['From', 'Billing <billing@some-shop.biz>'], ['To', 'me@example.org'], ['Subject', "Payment received - don't recognize it? Call +1 (818) 573-0808"]], 'Payment received. If you did not authorize this charge call us immediately.'));
    expect(r.findings.map((f) => f.id)).toContain('content.callback-phone');
    expect(r.verdict).toBe('danger');
  });
  it('spots homoglyph subjects, split words and personalised subjects', () => {
    const c = analyzeContent({ subject: '[jose] Тах Refund Νеw Νеssаցe', text: 'Lin ked i n Busi ne ss Invi tat ion Hi jo se , I d li ke to ad d you to my pro fes sion al net work on Lin ked In pl ea se ac ce pt th is in vi te', inReplyTo: null, references: null, hasLinks: true, hasAttachments: false, recipient: 'jose@monkey.org' });
    expect(c.subjectHomoglyph).toBe(true);
    expect(c.splitWords).toBe(true);
    expect(c.personalized).toBe('jose');
    expect(c.brandMentions).toContain('linkedin');
  });
  it('matches lure phrases in other languages', () => {
    const c = analyzeContent({ subject: 'Tu cuenta tiene problema en el pago', text: 'Actualice su contraseña para evitar que su cuenta sea suspendida.', inReplyTo: null, references: null, hasLinks: true, hasAttachments: false });
    expect(c.intents.length).toBeGreaterThan(0);
  });
});

describe('legitimate mail stays quiet', () => {
  it('does not flag a mailing-list reply', async () => {
    const r = await analyzeEmail(base([['From', 'Gavin <gavin@ucd.ie>'], ['To', 'ilug@linux.ie'], ['Reply-To', 'ilug@linux.ie'], ['List-Id', 'Irish Linux Users Group <ilug.linux.ie>'], ['Subject', 'Re: [ILUG] Got me a laptop']], 'Try the kernel from http://www.kernel.org/pub/linux/kernel/v2.4/linux-2.4.19.tar.gz and see http://example.org/howto.html'));
    expect(r.verdict).toBe('safe');
  });
});
