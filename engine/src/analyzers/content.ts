// Semantic content analysis: intent, pressure, requested action, brand mentions. Rule-based and
// explainable by design: every conclusion carries the phrases that triggered it.
import type { ContentAnalysis } from '../types';
import { ATTACHMENT_INSTRUCTIONS, EN_STOPWORDS, GENERIC_GREETINGS, INTENTS, URGENCY } from '../data/lexicon';
import { findBrands, findBrandsCollapsed } from '../data/brands';
import { collapseWs, hasMixedScriptWord, normalizeForMatching, scriptsOf, templatize, tokenize, truncate } from '../util/text';

function phraseRe(p: string): RegExp {
  // Phrases get the same normalization as the text (accents folded), so "contraseña" matches.
  const esc = normalizeForMatching(p).replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/\s+/g, '\\s+');
  return new RegExp(`(?:^|[^\\p{L}\\p{N}])${esc}(?=$|[^\\p{L}\\p{N}])`, 'u');
}

const COMPILED_INTENTS = INTENTS.map((i) => ({ ...i, compiled: i.phrases.map(([p, w]) => ({ p, w, re: phraseRe(p) })) }));
const COMPILED_URGENCY = URGENCY.map(([p, w]) => ({ p, w, re: phraseRe(p) }));
const COMPILED_ATTACH = ATTACHMENT_INSTRUCTIONS.map(([p, w]) => ({ p, w, re: phraseRe(p) }));
const COMPILED_GREETINGS = GENERIC_GREETINGS.map((g) => phraseRe(g));

// Legitimate short words in common languages, excluded from the split-word fragment count.
const SHORT_WORDS = new Set([
  'a', 'i', 'to', 'of', 'in', 'on', 'is', 'it', 'at', 'be', 'by', 'or', 'as', 'an', 'we', 'my', 'me', 'no', 'so', 'up', 'do', 'go', 'he', 'us', 'if', 'am', 'pm',
  'de', 'la', 'el', 'en', 'y', 'e', 'o', 'da', 'do', 'em', 'um', 'se', 'lo', 'le', 'du', 'et', 'il', 'di', 'un', 'zu', 'im', 'es', 'er', 'ab', 'ok', 'tv', 'id',
]);

const PHONE_RE =/(?:\+\d{1,3}[\s.-]?)?(?:\(\d{2,4}\)[\s.-]?)?\d{3,5}[\s.-]\d{3,4}[\s.-]?\d{0,4}/g;

export interface ContentInputs {
  subject: string;
  text: string; // best available body text (visible HTML text or text/plain)
  inReplyTo: string | null;
  references: string | null;
  hasLinks: boolean;
  hasAttachments: boolean;
  fromName?: string;
  recipient?: string | null;
}

export function analyzeContent(input: ContentInputs): ContentAnalysis {
  const subject = input.subject ?? '';
  const bodyNorm = normalizeForMatching(input.text.slice(0, 60_000));
  const subjNorm = normalizeForMatching(subject);
  // The sender's display name is part of the pitch ("Email Account Administrator").
  const all = `${subjNorm}\n${normalizeForMatching(input.fromName ?? '')}\n${bodyNorm}`;

  const intents = COMPILED_INTENTS.map((def) => {
    const matches: string[] = [];
    let score = 0;
    for (const { p, w, re } of def.compiled) {
      if (re.test(all)) {
        matches.push(p);
        // Phrases in the subject line are a stronger statement of intent.
        score += re.test(subjNorm) ? w * 1.3 : w;
      }
    }
    return { id: def.id, label: def.label, score: Math.round(score * 10) / 10, matches, action: def.action };
  })
    .filter((i) => i.score > 0)
    .sort((a, b) => b.score - a.score);

  let urgencyScore = 0;
  for (const { w, re } of COMPILED_URGENCY) if (re.test(all)) urgencyScore += re.test(subjNorm) ? w * 1.5 : w;
  const urgency: ContentAnalysis['urgency'] = urgencyScore >= 4.5 ? 3 : urgencyScore >= 2.5 ? 2 : urgencyScore >= 1 ? 1 : 0;

  const attachmentInstruction = COMPILED_ATTACH.filter(({ re }) => re.test(all)).map(({ p }) => p);
  const genericGreeting = COMPILED_GREETINGS.some((re) => re.test(bodyNorm.slice(0, 600)));

  const primary = intents[0] && intents[0].score >= 2.5 ? intents[0] : null;
  const actions = new Set<string>();
  if (primary?.action) actions.add(primary.action);
  if (input.hasLinks && (primary || urgency >= 2)) actions.add('click a link');
  if (attachmentInstruction.some((p) => /scan/.test(p))) actions.add('scan a QR code');
  else if (attachmentInstruction.length && input.hasAttachments) actions.add('open an attachment');

  const phones = new Set<string>();
  for (const m of input.text.slice(0, 20_000).matchAll(PHONE_RE)) {
    const digits = (m[0] as string).replace(/\D/g, '');
    if (digits.length >= 10 && digits.length <= 15 && !/^(19|20)\d{6}$/.test(digits)) phones.add(collapseWs(m[0] as string));
    if (phones.size >= 5) break;
  }
  if (phones.size && intents.some((i) => i.id === 'callback')) actions.add('call a phone number');

  // Split-word obfuscation: an unusual share of 1–2 letter fragments ("Lin ked i n Busi ne ss").
  const alpha = (input.text.slice(0, 4000).match(/\p{L}+/gu) ?? []).map((t) => t.toLowerCase());
  const fragments = alpha.filter((t) => t.length <= 2 && !SHORT_WORDS.has(t)).length;
  const splitWords = alpha.length >= 25 && fragments / alpha.length > 0.28;
  const brandSet = findBrands(`${subject}\n${input.text.slice(0, 20_000)}`, false);
  if (splitWords) for (const b of findBrandsCollapsed(`${subject} ${input.text}`)) if (!brandSet.includes(b)) brandSet.push(b);
  const brandMentions = brandSet.map((b) => b.id);

  const tokens = tokenize(`${subject} ${input.text.slice(0, 5000)}`);
  let language = 'unknown';
  if (tokens.length >= 5) {
    const en = tokens.filter((t) => EN_STOPWORDS.has(t)).length / tokens.length;
    if (en >= 0.08) language = 'en';
    else {
      const scripts = scriptsOf(input.text.slice(0, 2000));
      language = scripts.has('Devanagari') ? 'hi' : scripts.has('Cyrillic') ? 'ru' : scripts.has('Han') ? 'zh' : scripts.has('Arabic') ? 'ar' : 'other';
    }
  }

  const fakeReply = /^\s*(re|fw|fwd|aw|sv|vs|rif|tr)\s*:/i.test(subject) && !input.inReplyTo && !input.references;

  // Look-alike characters from other alphabets hidden in an otherwise Latin subject ("Тах Refund").
  const foreignLetters = subject.match(/[Ͱ-ϿЀ-ӿ԰-֏]/g)?.length ?? 0;
  const latinLetters = subject.match(/[a-z]/gi)?.length ?? 0;
  const subjectHomoglyph = hasMixedScriptWord(subject) || (foreignLetters > 0 && latinLetters > foreignLetters * 2);

  // Mass lures personalise with the victim's address: "[jose] Payment Confirmed", "for jose@monkey.org".
  let personalized: string | null = null;
  const rcpt = (input.recipient ?? '').toLowerCase();
  if (rcpt) {
    const local = rcpt.split('@')[0] ?? '';
    const s = subject.toLowerCase();
    if (s.includes(rcpt)) personalized = rcpt;
    else if (local.length >= 3 && new RegExp(`(^|[\\s[(<:"'])${local.replace(/[^a-z0-9._-]/g, '')}([\\s\\])>:,"'!?]|$)`).test(s) && !/^(re|fwd?):/i.test(s)) personalized = local;
  }
  const phoneInHeader = /(?:\+?\d[\d\s().-]{8,}\d)/.test(`${subject} ${input.fromName ?? ''}`) && ((`${subject} ${input.fromName ?? ''}`.match(/\d/g) ?? []).length >= 10);

  return {
    subject,
    subjectTemplate: templatize(subject),
    language,
    intent: primary?.id ?? null,
    intents: intents.map(({ id, label, score, matches }) => ({ id, label, score, matches: matches.slice(0, 8) })),
    urgency,
    requestedActions: [...actions],
    brandMentions,
    genericGreeting,
    phoneNumbers: [...phones],
    fakeReply,
    subjectHomoglyph,
    personalized,
    phoneInHeader,
    splitWords,
    attachmentInstructions: attachmentInstruction,
    textPreview: truncate(collapseWs(input.text), 280),
  };
}
