// Forensic classification model. Unlike the extension's three-way traffic light, it separates
// "nothing found because everything was examined" (benign) from "nothing found because the
// evidence was not there" (inconclusive), and only calls a message malicious when the risk score
// is backed by at least one strong, directly observed finding (or an exact threat-feed match).
//
// Confidence is a rule over three quantities, documented in docs/platform/DESIGN.md §5:
// the margin to the nearest decision threshold, evidence coverage, and the number of independent
// finding categories that agree. Its empirical precision is reported in docs/platform/VALIDATION.md.
import type { Classification, Confidence, EvidenceCoverage, Finding, ForensicClass, Severity } from './types';

export const DEFAULT_THRESHOLDS = { caution: 35, danger: 70, coverageFloor: 0.5 } as const;

const SEV: Record<Severity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

export function classify(
  score: number,
  findings: Finding[],
  coverage: EvidenceCoverage,
  t: { caution?: number; danger?: number; coverageFloor?: number } = {},
): Classification {
  const thresholds = {
    caution: t.caution ?? DEFAULT_THRESHOLDS.caution,
    danger: t.danger ?? DEFAULT_THRESHOLDS.danger,
    coverageFloor: t.coverageFloor ?? DEFAULT_THRESHOLDS.coverageFloor,
  };
  const positives = findings.filter((f) => f.weight > 0 && f.category !== 'integrity');
  const strong = positives.filter((f) => SEV[f.severity] >= 3 && f.category !== 'campaign');
  const intelHit = positives.some((f) => f.category === 'intel' || f.id === 'links.threat-intel');
  const categories = new Set(positives.filter((f) => SEV[f.severity] >= 2).map((f) => f.category));
  const maxSev = positives.reduce<Severity | null>((m, f) => (m === null || SEV[f.severity] > SEV[m] ? f.severity : m), null);
  const rationale: string[] = [];

  let cls: ForensicClass;
  if (score >= thresholds.danger && (strong.length > 0 || intelHit)) {
    cls = 'malicious';
    rationale.push(`Risk ${score} ≥ ${thresholds.danger} and ${intelHit ? 'an indicator is listed on a threat feed' : `${strong.length} high/critical finding${strong.length === 1 ? '' : 's'} observed directly in the message`}.`);
  } else if (score >= thresholds.caution) {
    cls = 'suspicious';
    rationale.push(score >= thresholds.danger ? `Risk ${score} ≥ ${thresholds.danger}, but no single finding is strong enough on its own: classified suspicious, not malicious.` : `Risk ${score} is between ${thresholds.caution} and ${thresholds.danger}.`);
  } else if (coverage.score < thresholds.coverageFloor) {
    cls = 'inconclusive';
    const missing = coverage.layers.filter((l) => l.status === 'absent').map((l) => l.label.toLowerCase());
    rationale.push(`Risk ${score} is low, but only ${Math.round(coverage.score * 100)}% of the evidence layers were available${missing.length ? ` (missing: ${missing.join(', ')})` : ''}; the absence of findings is not meaningful.`);
  } else {
    cls = 'benign';
    rationale.push(`Risk ${score} < ${thresholds.caution} with ${Math.round(coverage.score * 100)}% evidence coverage.`);
  }

  let confidence: Confidence;
  if (cls === 'malicious') {
    if (categories.size >= 2 && coverage.score >= 0.6) confidence = 'high';
    else if (coverage.score < 0.4) confidence = 'low';
    else confidence = 'medium';
    rationale.push(`${categories.size} independent categor${categories.size === 1 ? 'y' : 'ies'} of medium-or-higher findings (${[...categories].join(', ') || 'none'}).`);
  } else if (cls === 'suspicious') {
    const margin = Math.min(score - thresholds.caution, Math.abs(thresholds.danger - score));
    confidence = margin >= 10 && coverage.score >= 0.5 ? 'medium' : 'low';
    rationale.push('Suspicious is a call for review: confidence is never "high" for this class.');
  } else if (cls === 'benign') {
    // "No findings" is weak evidence: high confidence needs a clear margin, near-complete evidence and
    // not a single positive finding above informational (engine 1.2; see VALIDATION.md for why).
    const margin = thresholds.caution - score;
    const lowPlus = positives.some((f) => SEV[f.severity] >= 1);
    const mediumPlus = positives.some((f) => SEV[f.severity] >= 2);
    if (margin >= 20 && coverage.score >= 0.8 && !lowPlus) confidence = 'high';
    else if (margin < 10 || coverage.score < 0.6) confidence = 'low';
    else confidence = 'medium';
    if (mediumPlus) rationale.push('Some medium-severity findings were present but outweighed.');
    else if (lowPlus) rationale.push('Low-severity findings were present but outweighed.');
  } else {
    confidence = 'low';
  }

  const severity: Classification['severity'] = cls === 'malicious' || cls === 'suspicious' ? (maxSev && SEV[maxSev] >= 1 ? maxSev : 'low') : 'none';
  return { class: cls, severity, confidence, rationale, thresholds };
}
