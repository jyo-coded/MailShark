// Findings → risk. Each finding carries a logit weight; categories are capped so that one noisy
// area (e.g. 30 links) cannot dominate, and trust signals can never erase critical evidence.
import type {
  AttachmentAnalysis,
  AuthAnalysis,
  Category,
  Confidence,
  ContentAnalysis,
  EspInfo,
  Finding,
  HtmlAnalysis,
  IntelProvider,
  LinkAnalysis,
  RouteAnalysis,
  SenderAnalysis,
  Severity,
  StructureAnalysis,
  Verdict,
} from './types';
import { brandById, isBrandDomain } from './data/brands';
import { INVISIBLE_RE, STYLED_LETTERS_RE, truncate } from './util/text';

export const BIAS = -2.6;
export const DANGER_AT = 70;
export const CAUTION_AT = 35;

const CATEGORY_CAP: Record<Category, number> = {
  sender: 4.5, auth: 3, route: 1.5, links: 5, content: 3.5, html: 3.5, attachments: 6, structure: 2.5, intel: 5, campaign: 2.5,
};
const TRUST_FLOOR = -2.5;

export interface FindingsInput {
  sender: SenderAnalysis;
  auth: AuthAnalysis;
  route: RouteAnalysis;
  links: LinkAnalysis[];
  html: HtmlAnalysis;
  hiddenTextSample: string;
  content: ContentAnalysis;
  attachments: AttachmentAnalysis[];
  structure: StructureAnalysis;
  esp: EspInfo | null;
  xMailer: string | null;
  hasListUnsubscribe: boolean;
  isList: boolean;
  subject: string;
  intel: IntelProvider | null | undefined;
  senderSeenCount: number | null | undefined;
}

const BRAND_INTENTS = new Set(['credential', 'payment', 'delivery', 'document', 'tax', 'callback', 'reward', 'crypto', 'mfa']);

function f(id: string, category: Category, severity: Severity, weight: number, title: string, detail: string, evidence?: Finding['evidence']): Finding {
  return evidence && evidence.length ? { id, category, severity, weight, title, detail, evidence } : { id, category, severity, weight, title, detail };
}

function brandName(id: string | null): string {
  return (id && brandById(id)?.name) || id || 'a known brand';
}

export function buildFindings(x: FindingsInput): Finding[] {
  const out: Finding[] = [];
  const from = x.sender.from;
  const fromLabel = from ? (from.name ? `${from.name} <${from.address}>` : from.address) : 'unknown sender';

  // ── Sender identity ──
  if (x.sender.impersonatedBrand) {
    const b = brandName(x.sender.impersonatedBrand);
    // Using a brand's name is critical when paired with a lure, failed/absent authentication, a
    // free-mail or look-alike sender, or risky links. An authenticated bulk sender that merely
    // borrows a brand name (recruiters, resellers) is deceptive but not necessarily a trap.
    const authBad = x.auth.source === 'none' || x.auth.dmarc === 'fail' || x.auth.compauth === 'fail' || ((x.auth.spf === 'fail' || x.auth.spf === 'softfail') && x.auth.dkim !== 'pass');
    const lure = !!x.content.intent && BRAND_INTENTS.has(x.content.intent);
    const riskyLinks = x.links.some((l) => l.risk >= 2);
    const critical = authBad || lure || riskyLinks || x.sender.isFreemail || !!x.sender.lookalikeOf || x.attachments.some((at) => at.risk >= 2);
    out.push(f('sender.brand-impersonation', 'sender', critical ? 'critical' : 'high', critical ? 3.2 : 3.0, `Pretends to be ${b}`,
      `The sender presents itself as ${b}, but the message was not sent by a domain that belongs to ${b}.`,
      [{ label: 'From', value: fromLabel, mono: true }, { label: 'Real domain', value: from?.domain ?? 'n/a', mono: true }]));
  }
  if (x.sender.lookalikeOf && from) {
    const strong = x.sender.lookalikeKind === 'homoglyph' || x.sender.lookalikeKind === 'typosquat';
    out.push(
      strong
        ? f('sender.lookalike-domain', 'sender', 'critical', 3.0, 'Sender domain imitates a real brand',
            `${from.domain} is a look-alike of ${x.sender.lookalikeOf}: a classic trick to pass a quick glance.`, [{ label: 'Sender domain', value: from.domain, mono: true }])
        : f('sender.brand-in-domain', 'sender', 'medium', 1.0, 'Sender domain contains a brand name',
            `${from.domain} embeds the name of ${x.sender.lookalikeOf} without belonging to it.`, [{ label: 'Sender domain', value: from.domain, mono: true }]),
    );
  }
  const credentialLure = x.content.intent === 'credential' || x.content.intent === 'document';
  if (x.sender.impersonatesRecipientOrg && from) {
    const org = x.sender.impersonatesRecipientOrg;
    const inName = (from.name ?? '').toLowerCase().includes(org.split('.')[0] ?? org);
    const strong = inName || credentialLure;
    out.push(f('sender.recipient-org-lure', 'sender', strong ? 'critical' : 'medium', strong ? 3.0 : 1.0, `Poses as your own organisation (${org})`,
      `The message invokes ${org}, your own mail domain, but it was sent from ${from.orgDomain}. Your real IT team would write from inside ${org}.`,
      [{ label: 'From', value: fromLabel, mono: true }, { label: 'Your domain', value: org, mono: true }]));
  } else if (x.sender.roleName && from && !x.sender.verifiedBrand) {
    out.push(f('sender.role-name', 'sender', credentialLure ? 'high' : 'low', credentialLure ? 1.8 : 0.5, `Sender poses as “${x.sender.roleName}”`,
      `A generic IT/mail-system role name on an address at ${from.orgDomain}: a common disguise for mailbox and password lures.`,
      [{ label: 'From', value: fromLabel, mono: true }]));
  }
  const nameAndSubject = `${from?.name ?? ''} ${x.subject}`;
  if (INVISIBLE_RE.test(nameAndSubject)) {
    out.push(f('sender.invisible-chars', 'sender', 'high', 2.0, 'Invisible characters hidden in the sender name or subject',
      'Hidden Unicode characters are sprinkled between letters so filters cannot read brand names or keywords, while you still see them normally.'));
  }
  if (STYLED_LETTERS_RE.test(nameAndSubject)) {
    out.push(f('content.styled-letters', 'content', 'low', 0.6, 'Fancy Unicode lettering in the subject', 'Words are written with “mathematical” Unicode letters (𝐋𝐈𝐊𝐄 𝐓𝐇𝐈𝐒), a common way to dodge keyword filters.'));
  }
  if (!from || !from.address || !from.address.includes('@')) {
    out.push(f('sender.no-address', 'sender', 'medium', 1.0, 'No real sender address', 'The From field carries a name but no usable address: legitimate services always send from a real mailbox.'));
  }
  if (x.sender.displayNameAddress && from) {
    out.push(f('sender.display-name-address', 'sender', 'high', 2.0, 'Fake address shown in the sender name',
      `The name field shows "${x.sender.displayNameAddress}" but the email really comes from ${from.address}.`, [{ label: 'Actual address', value: from.address, mono: true }]));
  }
  if (from?.name && /[Ѐ-ӿͰ-Ͽ԰-֏]/.test(from.name) && /[a-z]/i.test(from.name)) {
    out.push(f('sender.homoglyph-name', 'sender', 'high', 1.8, 'Sender name mixes alphabets',
      'The display name mixes Latin letters with look-alike characters from other alphabets (homoglyphs).', [{ label: 'Display name', value: from.name }]));
  }
  if (from && x.sender.replyTo.length && !x.isList) {
    const rt = x.sender.replyTo.find((r) => r.orgDomain && r.orgDomain !== from.orgDomain);
    if (rt) {
      const rtFree = x.sender.isFreemail ? false : ['gmail.com', 'outlook.com', 'hotmail.com', 'yahoo.com', 'proton.me', 'protonmail.com', 'icloud.com', 'aol.com', 'mail.ru', 'yandex.ru', 'gmx.com'].includes(rt.orgDomain);
      const espReply = !!x.esp && x.auth.dmarc === 'pass';
      if (rtFree) out.push(f('sender.reply-to-freemail', 'sender', 'high', 1.8, 'Replies go to a free webmail account',
        `Hitting "Reply" sends your answer to ${rt.address}, not to ${from.domain}: typical of business-email-compromise scams.`, [{ label: 'Reply-To', value: rt.address, mono: true }]));
      else if (!espReply) out.push(f('sender.reply-to-mismatch', 'sender', 'medium', 0.9, 'Replies go to a different domain',
        `Replies are redirected to ${rt.orgDomain} instead of ${from.orgDomain}.`, [{ label: 'Reply-To', value: rt.address, mono: true }]));
    }
  }
  if (x.sender.isFreemail && x.content.intent && ['payment', 'bec', 'giftcard', 'job'].includes(x.content.intent)) {
    out.push(f('sender.freemail-business', 'sender', 'medium', 0.9, 'Business request from a personal webmail account',
      `A ${x.content.intents[0]?.label.toLowerCase() ?? 'business'} request sent from a free ${from?.domain} address.`));
  }
  if (x.sender.verifiedBrand) {
    out.push(f('sender.verified-brand', 'sender', 'info', -1.4, `Verified ${brandName(x.sender.verifiedBrand)} sender`,
      `The message is authenticated for a domain that belongs to ${brandName(x.sender.verifiedBrand)}.`));
  }
  if (x.isList && !x.sender.impersonatedBrand && !x.sender.impersonatesRecipientOrg) {
    out.push(f('route.mailing-list', 'route', 'info', -0.4, 'Discussion-list message', 'The message carries mailing-list headers (List-Id / Mailman), typical of group discussions rather than one-off lures.'));
  }
  if (x.senderSeenCount != null) {
    if (x.senderSeenCount >= 3) out.push(f('sender.known', 'sender', 'info', -0.7, 'Sender you hear from regularly', `You have received ${x.senderSeenCount} earlier emails from this address.`));
    else if (x.senderSeenCount === 0) out.push(f('sender.first-time', 'sender', 'low', 0.3, 'First email from this sender', 'MailShark has not seen this address in your mailbox before.'));
  }

  // ── Authentication ──
  const a = x.auth;
  if (a.source === 'none') {
    out.push(f('auth.none', 'auth', 'info', 0, 'No authentication results', 'This copy of the message carries no SPF/DKIM/DMARC verdicts from a receiving server, so the sender cannot be verified.'));
  } else {
    const ev = [
      { label: 'SPF', value: a.spf + (a.spfDomain ? ` (${a.spfDomain})` : '') },
      { label: 'DKIM', value: a.dkim + (a.dkimDomains.length ? ` (${a.dkimDomains.join(', ')})` : '') },
      { label: 'DMARC', value: a.dmarc + (a.dmarcPolicy ? ` (p=${a.dmarcPolicy})` : '') },
    ];
    if (a.dmarc === 'fail') out.push(f('auth.dmarc-fail', 'auth', 'high', 2.2, 'Sender domain rejected this message (DMARC fail)',
      `${a.headerFrom ?? 'The From domain'} publishes a DMARC policy, and this message failed it: the From address is very likely forged.`, ev));
    else if (a.compauth === 'fail') out.push(f('auth.compauth-fail', 'auth', 'high', 1.8, 'Microsoft composite authentication failed', 'Exchange Online could not verify that this message comes from the sender it claims.', ev));
    else if ((a.spf === 'fail' || a.spf === 'softfail') && a.dkim !== 'pass') out.push(f('auth.spf-fail', 'auth', 'medium', 1.0, 'Sent from a server the domain does not authorize (SPF)', 'The sending server is not on the sender domain\'s list of allowed mail servers, and no valid DKIM signature makes up for it.', ev));
    else if (a.dkim === 'fail' && a.spf !== 'pass') out.push(f('auth.dkim-fail', 'auth', 'medium', 0.8, 'Broken DKIM signature', 'The cryptographic signature does not match: the message was altered or forged.', ev));
    else if (a.dmarc === 'pass') out.push(f('auth.dmarc-pass', 'auth', 'info', -0.6, 'Sender domain verified (DMARC pass)', `${a.headerFrom ?? 'The From domain'} authorized this message.`, ev));
    else if (a.spfAligned === false && a.dkimAligned === false) out.push(f('auth.unaligned', 'auth', 'low', 0.4, 'Authentication does not cover the visible sender', 'SPF/DKIM passed for a different domain than the one shown in From, so the From address itself is unverified.', ev));
  }

  // ── Route ──
  if (x.route.originIp) {
    out.push(f('route.origin', 'route', 'info', 0, `Origin server: ${x.route.originHost ?? x.route.originIp}`,
      `The receiving server recorded the message arriving from ${x.route.originHost ? `${x.route.originHost} ` : ''}[${x.route.originIp}].`,
      [{ label: 'Origin IP', value: x.route.originIp, mono: true }, ...(x.route.originHost ? [{ label: 'Host', value: x.route.originHost, mono: true }] : [])]));
  }
  if (x.route.dateSkewSec !== null && Math.abs(x.route.dateSkewSec) > 86_400) {
    const days = Math.round(Math.abs(x.route.dateSkewSec) / 86_400);
    out.push(f('route.date-skew', 'route', days > 7 ? 'medium' : 'low', days > 7 ? 0.8 : 0.4, 'Date header does not match delivery time',
      `The email claims to have been written ${days} day${days === 1 ? '' : 's'} ${x.route.dateSkewSec > 0 ? 'before' : 'after'} it actually arrived.`));
  }

  // ── Links ──
  const anchorLinks = x.links.filter((l) => l.sources.some((s) => s === 'html-anchor' || s === 'text' || s === 'qr' || s === 'attachment' || s === 'html-form'));
  const addLink = (id: string, severity: Severity, weight: number, title: string, detail: string, links: LinkAnalysis[]): void => {
    if (!links.length) return;
    out.push(f(id, 'links', severity, weight, title, detail, links.slice(0, 4).map((l) => ({ label: l.displayText ? truncate(l.displayText, 40) : 'Link', value: truncate(l.url, 160), mono: true }))));
  };
  addLink('links.threat-intel', 'critical', 4.0, 'Link to a known malicious site', 'A link points to a domain listed on a public threat-intelligence feed.', anchorLinks.filter((l) => l.intelHit));
  addLink('links.lookalike', 'critical', 3.0, 'Link to a look-alike domain', 'A link imitates a real brand domain with swapped or extra characters.', anchorLinks.filter((l) => l.flags.includes('lookalike-homoglyph') || l.flags.includes('lookalike-typosquat')));
  const lureContext = !!x.content.intent && BRAND_INTENTS.has(x.content.intent);
  addLink('links.brand-embedded', lureContext ? 'high' : 'medium', lureContext ? 1.8 : 0.8, 'Link hides a brand name inside another domain', 'A link uses a brand name as a decoy within an unrelated domain (e.g. paypal.com.secure-check.xyz).', anchorLinks.filter((l) => l.flags.includes('lookalike-embedded') || l.flags.includes('lookalike-subdomain')));
  addLink('links.text-mismatch', 'high', 2.2, 'Link text lies about its destination', 'The visible link text shows one website, but clicking it opens a different one.', anchorLinks.filter((l) => l.flags.includes('text-href-mismatch')));
  addLink('links.ip-host', 'high', 2.0, 'Link points to a raw IP address', 'Legitimate services almost never send links to bare IP addresses.', anchorLinks.filter((l) => l.flags.includes('ip-host')));
  addLink('links.punycode', 'high', 1.8, 'Link uses an internationalized (punycode) domain', 'The domain contains non-Latin characters that can visually mimic a familiar name.', anchorLinks.filter((l) => l.flags.includes('punycode') || l.flags.includes('mixed-script')));
  addLink('links.script-uri', 'high', 2.2, 'Link runs code instead of opening a page', 'javascript:/data: links execute content directly.', x.links.filter((l) => l.flags.some((fl) => /-uri$/.test(fl))));
  addLink('links.credentials-in-url', 'high', 2.0, 'Link hides its real destination behind an @', 'Everything before "@" in a URL is ignored by the browser: a disguise trick.', anchorLinks.filter((l) => l.flags.includes('credentials-in-url')));
  addLink('links.ipfs', 'high', 1.8, 'Link to decentralized (IPFS) hosting', 'IPFS pages cannot be taken down easily and are popular for phishing kits.', anchorLinks.filter((l) => l.flags.includes('ipfs')));
  const credIntent = x.content.intent === 'credential' || x.content.intent === 'document';
  addLink('links.free-hosting', credIntent ? 'high' : 'medium', credIntent ? 1.6 : 0.9, 'Link to a free website / form builder', 'Anyone can create a page on these platforms in minutes: they are heavily abused for fake login pages.', anchorLinks.filter((l) => l.flags.includes('free-hosting') || l.flags.includes('form-service')));
  addLink('links.file-download', 'high', 1.6, 'Link downloads a program or script', 'The link points straight at an executable, script, disk image or macro document.', anchorLinks.filter((l) => l.flags.includes('file-download')));
  addLink('links.archive-download', 'low', 0.3, 'Link downloads an archive', 'Archives can hide malware from scanners; open only what you expected.', anchorLinks.filter((l) => l.flags.includes('archive-download')));
  addLink('links.nonstandard-port', 'medium', 0.8, 'Link uses an unusual network port', 'Web links rarely specify custom ports.', anchorLinks.filter((l) => l.flags.includes('nonstandard-port')));
  addLink('links.shortener', 'low', 0.5, 'Shortened link hides the destination', 'URL shorteners conceal where a link really goes.', anchorLinks.filter((l) => l.flags.includes('shortener')));
  addLink('links.suspicious-tld', 'low', 0.4, 'Link on a high-abuse domain ending', 'Some domain endings are disproportionately used by attackers.', anchorLinks.filter((l) => l.flags.includes('suspicious-tld')));
  addLink('links.redirect', 'low', 0.4, 'Link bounces through a redirect', 'The link passes you on to another site via a URL parameter.', anchorLinks.filter((l) => l.flags.includes('redirect-param')));

  // Brand mentioned with a lure, but neither sender nor links belong to that brand.
  const lure = x.content.intents[0];
  if (lure && lure.score >= 4 && BRAND_INTENTS.has(lure.id) && !x.sender.verifiedBrand && !x.sender.impersonatedBrand) {
    const head = `${x.subject} ${from?.name ?? ''} ${x.content.textPreview.slice(0, 280)}`.toLowerCase();
    for (const bid of x.content.brandMentions) {
      const brand = brandById(bid);
      if (!brand || !from) continue;
      if (isBrandDomain(brand, from.orgDomain)) continue;
      if (!brand.names.some((n) => head.includes(n))) continue;
      // Phishers often sprinkle genuine brand links for credibility; what matters is a call to
      // action pointing somewhere that is neither the brand, the sender, nor mail tracking.
      const linkDomains = anchorLinks
        .filter((l) => !l.flags.includes('unsubscribe') && !l.flags.includes('esp-tracking'))
        .map((l) => l.regDomain)
        .filter((d): d is string => !!d && !isBrandDomain(brand, d) && d !== from.orgDomain);
      if (linkDomains.length) {
        out.push(f('content.brand-lure', 'content', 'high', 1.8, `Uses the ${brand.name} name, but isn't from ${brand.name}`,
          `The message talks about your ${brand.name} account/order, yet it was sent by ${from.orgDomain} and its links lead elsewhere.`,
          [{ label: 'Sender', value: from.address, mono: true }, { label: 'Links to', value: [...new Set(linkDomains)].slice(0, 3).join(', '), mono: true }]));
        break;
      }
    }
  }

  // ── HTML ──
  const h = x.html;
  if (h.forms.some((fm) => fm.hasPassword)) out.push(f('html.credential-form', 'html', 'critical', 3.0, 'Password form inside the email', 'The email itself contains a password field: real services never ask you to type credentials into an email.'));
  else if (h.forms.length) out.push(f('html.form', 'html', 'low', 0.6, 'Embedded form collects data', 'The email contains an input form that can submit what you type to a third party.', h.forms.slice(0, 2).map((fm) => ({ label: 'Form action', value: fm.action ?? '(none)', mono: true }))));
  if (h.scripts > 0) out.push(f('html.script', 'html', 'low', 0.6, 'Contains scripts', `${h.scripts} <script> element(s): email clients block them, so their presence is a red flag.`));
  if (h.iframes + h.embeds > 0) out.push(f('html.iframe', 'html', 'low', 0.4, 'Embeds external frames/objects', 'Frames and embedded objects are used to smuggle remote content into messages.'));
  if (h.metaRefresh) out.push(f('html.meta-refresh', 'html', 'medium', 1.0, 'Auto-redirect instruction', 'A meta-refresh tag tries to send you to another page automatically.', [{ label: 'Refresh', value: truncate(h.metaRefresh, 120), mono: true }]));
  if (h.hiddenTextChars > 120 && h.hiddenTextChars > h.visibleTextChars * 0.25) {
    out.push(f('html.hidden-text', 'html', 'medium', 1.2, 'Hidden text to fool spam filters', `${h.hiddenTextChars} characters are invisible to you but readable by filters ("hidden text salting").`,
      x.hiddenTextSample ? [{ label: 'Hidden sample', value: truncate(x.hiddenTextSample, 140) }] : undefined));
  }
  if (h.zeroWidthChars >= 5) out.push(f('html.zero-width', 'html', 'medium', 0.9, 'Invisible characters break up words', `${h.zeroWidthChars} zero-width characters are inserted to dodge keyword detection.`));
  if (h.imageOnly && anchorLinks.length) out.push(f('html.image-only', 'html', 'low', 0.6, 'Message is mostly an image', 'Text rendered as an image hides the wording from security filters.'));
  if (h.imageOnly && h.hiddenTextChars > 120) out.push(f('html.image-with-filler', 'html', 'high', 1.2, 'Picture-only message padded with invisible text', 'The visible message is a picture while hidden filler text feeds the spam filter: a combined evasion technique.'));
  if (h.trackingPixels > 0 || x.links.some((l) => l.flags.includes('tracking'))) out.push(f('html.tracking', 'html', 'info', 0, 'Reports back when you open it', 'The email contains a tracking pixel: opening it (with images on) tells the sender you read it.'));

  // ── Content ──
  const c = x.content;
  const top = c.intents[0];
  if (top && top.score >= 2.5) {
    const strong = top.score >= 5;
    const weight = Math.min(2.4, 0.3 * top.score + (c.urgency >= 2 ? 0.4 : 0));
    out.push(f(`content.intent.${top.id}`, 'content', strong && c.urgency >= 2 ? 'high' : strong ? 'medium' : 'low', weight, `Reads like ${top.label.toLowerCase()}`,
      c.requestedActions.length ? `It pushes you to ${c.requestedActions.join(', ')}.` : 'Its wording matches a known phishing playbook.',
      [{ label: 'Trigger phrases', value: top.matches.slice(0, 5).map((m) => `"${m}"`).join(', ') }]));
  }
  if (c.subjectHomoglyph) out.push(f('content.homoglyph-subject', 'content', 'high', 1.8, 'Subject disguises letters with look-alikes', 'Some letters in the subject come from other alphabets (e.g. Cyrillic “а” instead of “a”) to slip past keyword filters.', [{ label: 'Subject', value: x.subject }]));
  if (c.personalized) out.push(f('content.personalized-subject', 'content', credIntent || c.intent === 'payment' ? 'medium' : 'low', credIntent || c.intent === 'payment' ? 1.0 : 0.4, 'Your address is used as bait in the subject', `Mass-mailed lures paste the recipient's address (“${c.personalized}”) into the subject to look personal.`));
  const callbackScore = c.intents.find((i) => i.id === 'callback')?.score ?? 0;
  const payLike = c.intents.some((i) => (i.id === 'callback' || i.id === 'payment') && i.score >= 1.5);
  if (c.phoneInHeader && (payLike || c.brandMentions.length || x.sender.claimedBrands.length)) {
    // A support number in the subject/sender name is almost never legitimate; it is also how
    // attackers abuse genuine invoicing systems (e.g. real PayPal invoices), so it stays critical
    // even when the sending domain authenticates.
    out.push(f('content.callback-phone', 'content', payLike ? 'critical' : 'high', payLike ? 3.0 : 2.0, 'Phone number planted in the sender name or subject', 'Call-back scams put a “support” number where you will see it first, then ask you to call and pay or grant remote access.', c.phoneNumbers.length ? [{ label: 'Number', value: c.phoneNumbers[0] as string, mono: true }] : undefined));
  } else if (c.phoneNumbers.length && callbackScore >= 2.5) {
    const strong = c.brandMentions.length > 0 || callbackScore >= 4;
    out.push(f('content.callback-phone', 'content', strong ? 'high' : 'medium', strong ? 1.8 : 1.2, 'Asks you to call a phone number', 'The message pushes you to call a number about a charge, order or renewal: the hallmark of call-back (TOAD) scams.', [{ label: 'Number', value: c.phoneNumbers[0] as string, mono: true }]));
  }
  if (c.splitWords) out.push(f('content.split-words', 'content', 'medium', 1.2, 'Words broken up to dodge filters', 'Many words in the message are split with spaces (“Lin ked i n”), a trick to stop keyword filters from reading it.'));
  if (c.urgency >= 2) out.push(f('content.urgency', 'content', c.urgency === 3 ? 'medium' : 'low', c.urgency === 3 ? 1.0 : 0.5, 'Creates pressure to act fast', 'Deadlines and threats are designed to make you skip careful thinking.'));
  if (c.genericGreeting) out.push(f('content.generic-greeting', 'content', 'low', 0.3, 'Generic greeting', 'It doesn\'t address you by name, as mass-mailed lures usually don\'t.'));
  if (c.fakeReply) out.push(f('content.fake-reply', 'content', 'medium', 1.2, 'Pretends to be part of a conversation', 'The subject starts with "Re:"/"Fwd:" but the message is not a reply to anything you sent.'));
  const risky = c.attachmentInstructions.filter((p) => /enable|macros/.test(p));
  if (risky.length) out.push(f('content.enable-content', 'content', 'critical', 2.6, 'Tells you to enable macros/content', 'Enabling editing or macros in a document is how most malware attachments activate.', [{ label: 'Phrases', value: risky.join(', ') }]));
  if (c.attachmentInstructions.some((p) => /password/.test(p)) && x.attachments.some((at) => at.flags.includes('encrypted-archive') || at.flags.includes('encrypted-office'))) {
    out.push(f('content.password-archive', 'content', 'high', 1.6, 'Password-protected file with the password in the email', 'Encrypting the file with a password in the message body is a trick to stop scanners inspecting it.'));
  }

  // ── Attachments ──
  for (const at of x.attachments) {
    const has = (...fl: string[]): boolean => fl.some((q) => at.flags.includes(q));
    const ev = [{ label: 'File', value: at.filename }, { label: 'Real type', value: at.detectedType }, { label: 'SHA-256', value: at.sha256, mono: true }];
    if (has('executable', 'archive-executable', 'disk-image', 'archive-disk-image', 'double-extension', 'rtlo-filename', 'padded-filename'))
      out.push(f(`attachments.executable:${at.sha256.slice(0, 8)}`, 'attachments', 'critical', 3.5, `Dangerous file: ${truncate(at.filename, 48)}`, 'This attachment can run code on your computer (executable, disk image or disguised extension).', ev));
    else if (has('html-credential-form', 'html-smuggling-script'))
      out.push(f(`attachments.html-phish:${at.sha256.slice(0, 8)}`, 'attachments', 'critical', 3.2, `Attached web page is a phishing kit: ${truncate(at.filename, 40)}`, 'The HTML/SVG attachment contains a login form or code that assembles a hidden payload (HTML smuggling).', ev));
    else if (has('office-macros', 'office-remote-template', 'office-dde', 'rtf-embedded-object', 'pdf-autorun-script'))
      out.push(f(`attachments.active-content:${at.sha256.slice(0, 8)}`, 'attachments', 'high', 2.5, `Document with active content: ${truncate(at.filename, 40)}`, `Contains ${at.flags.filter((q) => /macro|template|dde|object|autorun/.test(q)).join(', ')}: document-based malware.`, ev));
    else if (has('macro-enabled-office', 'onenote', 'type-mismatch', 'encrypted-archive', 'html-attachment', 'svg-attachment', 'pdf-javascript', 'pdf-launch', 'archive-html', 'archive-macro-office', 'html-redirect', 'html-form'))
      out.push(f(`attachments.risky:${at.sha256.slice(0, 8)}`, 'attachments', 'high', 1.7, `Risky attachment: ${truncate(at.filename, 48)}`, `Flags: ${at.flags.join(', ')}.`, ev));
    else if (has('qr-code'))
      out.push(f(`attachments.qr:${at.sha256.slice(0, 8)}`, 'attachments', 'medium', 1.2, 'Image contains a QR code', `The QR code leads to ${truncate(at.qr ?? 'an unknown target', 80)}: QR codes move you to your phone, outside company protection ("quishing").`, [{ label: 'Decoded', value: at.qr ?? '', mono: true }]));
    else if (has('pdf-link-lure', 'uninspectable-archive', 'nested-archive', 'calendar-links'))
      out.push(f(`attachments.note:${at.sha256.slice(0, 8)}`, 'attachments', 'low', 0.5, `Attachment worth a second look: ${truncate(at.filename, 40)}`, `Flags: ${at.flags.join(', ')}.`, ev));
  }

  // ── Structure ──
  const s = x.structure;
  const dangerousDupes = s.duplicateHeaders.filter((d) => ['from', 'subject', 'to', 'date', 'message-id', 'reply-to', 'sender', 'content-type'].includes(d));
  if (dangerousDupes.length) out.push(f('structure.duplicate-headers', 'structure', 'high', 1.8, 'Duplicate critical headers', 'Two conflicting copies of the same header can make different programs show different senders (parser-confusion attack).', [{ label: 'Duplicated', value: dangerousDupes.join(', '), mono: true }]));
  if (s.anomalies.length) out.push(f('structure.anomalies', 'structure', 'low', 0.4, 'Malformed MIME structure', 'The message structure is broken in ways normal mail software does not produce.', [{ label: 'Anomalies', value: s.anomalies.join(', '), mono: true }]));
  if (s.textHtmlDivergence !== null && s.textHtmlDivergence > 0.85) out.push(f('structure.divergence', 'structure', 'low', 0.4, 'Text and HTML versions say different things', 'The plain-text part (what filters read) differs from the HTML part (what you see).'));

  // ── Bulk infrastructure & tooling ──
  if (x.esp && !['phpmailer', 'gammadyne', 'sendblaster'].includes(x.esp.id)) {
    const legit = x.auth.dmarc === 'pass' && x.hasListUnsubscribe;
    out.push(f('route.esp', 'route', 'info', legit ? -0.5 : 0, `Sent through ${x.esp.name}`,
      `Bulk-mail infrastructure (${x.esp.evidence})${x.esp.campaignId ? `, campaign #${x.esp.campaignId}` : ''}${x.esp.customerId ? `, customer #${x.esp.customerId}` : ''}.`,
      [...(x.esp.campaignId ? [{ label: 'Campaign ID', value: x.esp.campaignId, mono: true }] : []), ...(x.esp.customerId ? [{ label: 'Customer ID', value: x.esp.customerId, mono: true }] : [])]));
  }
  if (x.xMailer && /phpmailer|gammadyne|sendblaster|leaf|atomic mail|turbo-mailer|ultimate mailer|mass mailer|superMailer/i.test(x.xMailer)) {
    out.push(f('route.mass-mailer', 'route', 'medium', 0.8, 'Sent by a mass-mailing script', `X-Mailer "${truncate(x.xMailer, 60)}" is common on compromised web servers and spam kits.`));
  }

  // ── Threat intel on the sender ──
  if (x.intel && from) {
    const hit = x.intel.lookupDomain(from.domain) ?? x.intel.lookupDomain(from.orgDomain);
    if (hit) out.push(f('intel.sender-domain', 'intel', 'critical', 4.0, 'Sender domain is on a threat feed', `${from.orgDomain} appears in ${hit}.`));
  }

  return out;
}

export interface ScoreResult {
  score: number;
  verdict: Verdict;
  confidence: Confidence;
  headline: string;
  oneLiner: string;
}

const SEVERITY_RANK: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

export function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || b.weight - a.weight);
}

export function scoreFindings(findings: Finding[], authSource: AuthAnalysis['source'], textChars: number): ScoreResult {
  const perCat = new Map<Category, number>();
  let trust = 0;
  for (const fi of findings) {
    if (fi.weight < 0) trust += fi.weight;
    else if (fi.weight > 0) perCat.set(fi.category, (perCat.get(fi.category) ?? 0) + fi.weight);
  }
  let risk = 0;
  for (const [cat, sum] of perCat) risk += Math.min(sum, CATEGORY_CAP[cat]);
  const hasCritical = findings.some((fi) => fi.severity === 'critical');
  // Trust can offset noise, but it cannot cancel critical evidence (e.g. a hijacked real account).
  trust = Math.max(TRUST_FLOOR, trust) * (hasCritical ? 0.35 : 1);
  const logit = BIAS + risk + trust;
  let score = Math.round(100 / (1 + Math.exp(-logit)));
  if (hasCritical) score = Math.max(score, DANGER_AT + 5);
  score = Math.max(1, Math.min(99, score));
  const verdict: Verdict = score >= DANGER_AT ? 'danger' : score >= CAUTION_AT ? 'caution' : 'safe';

  const positives = findings.filter((fi) => fi.weight > 0).length;
  let confidence: Confidence = 'medium';
  if (authSource === 'trusted' && (score >= 85 || (score <= 15 && positives <= 1))) confidence = 'high';
  else if (authSource === 'none' && textChars < 80 && positives <= 1) confidence = 'low';
  else if (hasCritical && positives >= 3) confidence = 'high';

  const sorted = sortFindings(findings).filter((fi) => fi.weight > 0);
  const trustFinding = sortFindings(findings).find((fi) => fi.weight < 0);
  const headline = verdict === 'danger' ? 'Likely phishing' : verdict === 'caution' ? 'Be careful' : 'Looks safe';
  const oneLiner =
    verdict === 'safe'
      ? (trustFinding?.title ?? (sorted[0] && sorted[0].severity !== 'low' ? sorted[0].title : 'No warning signs found'))
      : (sorted[0]?.title ?? 'Several weak warning signs');
  return { score, verdict, confidence, headline, oneLiner };
}
