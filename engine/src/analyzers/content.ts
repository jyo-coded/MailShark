// Semantic content analysis: intent, pressure, requested action, brand mentions. Rule-based and
// explainable by design: every conclusion carries the phrases that triggered it.
import type { ContentAnalysis } from '../types';
import { ATTACHMENT_INSTRUCTIONS, EN_STOPWORDS, GENERIC_GREETINGS, INTENTS, URGENCY } from '../data/lexicon';
import { findBrands } from '../data/brands';
import { collapseWs, normalizeForMatching, scriptsOf, templatize, tokenize, truncate } from '../util/text';

function phraseRe(p: string): RegExp {
  const esc = p.replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/\s+/g, '\\s+');
  return new RegExp(`(?:^|[^\\p{L}\\p{N}])${esc}(?=$|[^\\p{L}\\p{N}])`, 'u');
}

const COMPILED_INTENTS = INTENTS.map((i) => ({ ...i, compiled: i.phrases.map(([p, w]) => ({ p, w, re: phraseRe(p) })) }));
const COMPILED_URGENCY = URGENCY.map(([p, w]) => ({ p, w, re: phraseRe(p) }));
const COMPILED_ATTACH = ATTACHMENT_INSTRUCTIONS.map(([p, w]) => ({ p, w, re: phraseRe(p) }));
const COMPILED_GREETINGS = GENERIC_GREETINGS.map((g) => phraseRe(g));

const PHONE_RE = /(?:\+\d{1,3}[\s.-]?)?(?:\(\d{2,4}\)[\s.-]?)?\d{3,5}[\s.-]\d{3,4}[\s.-]?\d{0,4}/g;

export interface ContentInputs {
  subject: string;
  text: string; // best available body text (visible HTML text or text/plain)
  inReplyTo: string | null;
  references: string | null;
  hasLinks: boolean;
  hasAttachments: boolean;
}

export function analyzeContent(input: ContentInputs): ContentAnalysis {
  const subject = input.subject ?? '';
  const bodyNorm = normalizeForMatching(input.text.slice(0, 60_000));
  const subjNorm = normalizeForMatching(subject);
  const all = `${subjNorm}\n${bodyNorm}`;

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

  const brandMentions = findBrands(`${subject}\n${input.text.slice(0, 20_000)}`, false).map((b) => b.id);

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
    attachmentInstructions: attachmentInstruction,
    textPreview: truncate(collapseWs(input.text), 280),
  };
}
