// Design aid for the benign-confidence rule: on the TUNE split only, compares the evidence behind
// "benign" calls for legitimate mail and for missed phishing.
//   node scripts/eval/run.mjs benign-analysis
import { analyzeEmail } from '../../engine/src/analyze';
import { samples, splitOf } from './corpus';

interface Acc {
  n: number;
  [k: string]: number;
}
const acc: Record<'ham' | 'phish', Acc> = { ham: { n: 0 }, phish: { n: 0 } };
const inc = (a: Acc, k: string): void => {
  a[k] = (a[k] ?? 0) + 1;
};
for (const s of samples(process.cwd())) {
  if (splitOf(s.raw) !== 'tune') continue;
  const r = await analyzeEmail(s.raw, { now: new Date('2026-09-21T00:00:00Z') });
  if (r.classification?.class !== 'benign') continue;
  const a = acc[s.label];
  a.n++;
  const au = r.auth;
  const attributed = au.source === 'trusted';
  if (attributed) inc(a, 'auth:attributed');
  if (au.source === 'topmost') inc(a, 'auth:unattributed');
  if (au.source === 'none') inc(a, 'auth:none');
  if (attributed && au.dmarc === 'pass') inc(a, 'dmarc:pass(attributed)');
  if (attributed && (au.dkim === 'pass' && au.dkimAligned)) inc(a, 'dkim:aligned-pass(attributed)');
  if (attributed && au.spf === 'pass' && au.spfAligned) inc(a, 'spf:aligned-pass(attributed)');
  const selfDkim = (r.dkim ?? []).some((d) => d.bodyHash === 'pass' && d.coversFrom && r.sender.from && (d.domain === r.sender.from.orgDomain || r.sender.from.domain.endsWith('.' + d.domain) || d.domain === r.sender.from.domain));
  if (selfDkim) inc(a, 'dkim:body-hash-ok-from-domain');
  if (r.findings.some((f) => f.weight < 0)) inc(a, 'trust-finding');
  if (r.esp) inc(a, 'esp');
  if (r.headers.some((h) => /^list-(id|unsubscribe)$/i.test(h.name))) inc(a, 'list-headers');
  if (r.links.length === 0) inc(a, 'no-links');
  if (r.links.some((l) => l.risk >= 1)) inc(a, 'some-link-note');
  if (r.content.intent) inc(a, 'intent-detected');
  if (r.sender.isFreemail) inc(a, 'freemail');
  if (r.route.hops.length === 0) inc(a, 'no-received');
  if (r.classification.confidence === 'high') inc(a, 'conf:high');
  if ((r.coverage?.score ?? 0) >= 0.8) inc(a, 'coverage>=0.8');
  if (r.score < 15) inc(a, 'score<15');
  if (r.findings.some((f) => f.weight > 0 && (f.severity === 'low' || f.severity === 'medium'))) inc(a, 'has-low/med-finding');
}
const keys = [...new Set([...Object.keys(acc.ham), ...Object.keys(acc.phish)])].filter((k) => k !== 'n').sort();
console.log(`benign calls on TUNE split: ham ${acc.ham.n}, missed phishing ${acc.phish.n}`);
console.log('feature'.padEnd(34) + 'ham%'.padStart(8) + 'phish%'.padStart(9));
for (const k of keys) console.log(k.padEnd(34) + (((100 * (acc.ham[k] ?? 0)) / acc.ham.n).toFixed(1)).padStart(8) + (((100 * (acc.phish[k] ?? 0)) / acc.phish.n).toFixed(1)).padStart(9));
