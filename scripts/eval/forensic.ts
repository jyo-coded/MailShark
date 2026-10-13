// Forensic-classification evaluation: the platform's classes (malicious / suspicious / inconclusive /
// benign) and their confidence levels, on a deterministic content-hash split (tune ≈70%, holdout ≈30%).
//   node scripts/eval/run.mjs forensic [--limit N] [--out lab/out/forensic-eval.json]
// Thresholds are the platform defaults; they were not re-tuned on either split for this report.
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { analyzeEmail, ENGINE_VERSION } from '../../engine/src/analyze';
import { DEFAULT_THRESHOLDS } from '../../engine/src/classify';
import { corpusStats, samples, splitOf } from './corpus';

const args = process.argv.slice(2);
const arg = (k: string): string | null => (args.includes(k) ? (args[args.indexOf(k) + 1] as string) : null);
const limit = Number(arg('--limit') ?? 0) || Infinity;
const outPath = arg('--out') ?? 'lab/out/forensic-eval.json';

type Cls = 'malicious' | 'suspicious' | 'inconclusive' | 'benign' | 'failed';
interface Row {
  split: 'tune' | 'holdout';
  dataset: string;
  label: 'phish' | 'ham';
  cls: Cls;
  confidence: string;
  coverage: number;
}

const rows: Row[] = [];
const t0 = Date.now();
let n = 0;
for (const s of samples(process.cwd(), limit)) {
  let cls: Cls = 'failed';
  let confidence = 'low';
  let coverage = 0;
  try {
    const r = await analyzeEmail(s.raw, { now: new Date('2026-09-21T00:00:00Z'), thresholds: DEFAULT_THRESHOLDS });
    cls = (r.classification?.class ?? 'failed') as Cls;
    confidence = r.classification?.confidence ?? 'low';
    coverage = r.coverage?.score ?? 0;
  } catch {
    cls = 'failed';
  }
  rows.push({ split: splitOf(s.raw), dataset: s.dataset, label: s.label, cls, confidence, coverage });
  if (++n % 2000 === 0) process.stderr.write(`  ${n} messages (${Math.round((Date.now() - t0) / 1000)}s)\n`);
}

const pct = (x: number, d: number): number | null => (d ? Math.round((1000 * x) / d) / 10 : null);
function metrics(rs: Row[]): Record<string, unknown> {
  const phish = rs.filter((r) => r.label === 'phish');
  const ham = rs.filter((r) => r.label === 'ham');
  const count = (xs: Row[], f: (r: Row) => boolean): number => xs.filter(f).length;
  const flagged = (r: Row): boolean => r.cls === 'malicious' || r.cls === 'suspicious';
  const tp = count(phish, flagged);
  const fp = count(ham, flagged);
  const confusion: Record<string, Record<string, number>> = {};
  for (const r of rs) {
    confusion[r.label] ??= {};
    (confusion[r.label] as Record<string, number>)[r.cls] = ((confusion[r.label] as Record<string, number>)[r.cls] ?? 0) + 1;
  }
  const byConfidence: Record<string, unknown> = {};
  for (const cls of ['malicious', 'benign'] as const) {
    for (const conf of ['high', 'medium', 'low']) {
      const sel = rs.filter((r) => r.cls === cls && r.confidence === conf);
      const correct = sel.filter((r) => (cls === 'malicious' ? r.label === 'phish' : r.label === 'ham')).length;
      byConfidence[`${cls}/${conf}`] = { n: sel.length, correctPct: pct(correct, sel.length) };
    }
  }
  // Rates conditioned on the true label do not depend on the corpus' phishing share; precision does.
  const rate = (xs: Row[], f: (r: Row) => boolean): number | null => pct(count(xs, f), xs.length);
  const benignHighHam = rate(ham, (r) => r.cls === 'benign' && r.confidence === 'high');
  const benignHighPhish = rate(phish, (r) => r.cls === 'benign' && r.confidence === 'high');
  const atPrevalence = (pi: number): number | null =>
    benignHighHam === null || benignHighPhish === null || benignHighHam + benignHighPhish === 0 ? null : Math.round((1000 * ((1 - pi) * benignHighHam)) / ((1 - pi) * benignHighHam + pi * benignHighPhish)) / 10;
  const mal = rs.filter((r) => r.cls === 'malicious');
  const ben = rs.filter((r) => r.cls === 'benign');
  return {
    messages: rs.length,
    phishing: phish.length,
    legitimate: ham.length,
    recallFlaggedPct: pct(tp, phish.length),
    falsePositiveRatePct: pct(fp, ham.length),
    falseNegativeRatePct: pct(phish.length - tp, phish.length),
    precisionFlaggedPct: pct(tp, tp + fp),
    maliciousPrecisionPct: pct(mal.filter((r) => r.label === 'phish').length, mal.length),
    maliciousRecallPct: pct(count(phish, (r) => r.cls === 'malicious'), phish.length),
    legitimateCalledMaliciousPct: pct(count(ham, (r) => r.cls === 'malicious'), ham.length),
    benignNpvPct: pct(ben.filter((r) => r.label === 'ham').length, ben.length),
    inconclusivePct: { phishing: pct(count(phish, (r) => r.cls === 'inconclusive'), phish.length), legitimate: pct(count(ham, (r) => r.cls === 'inconclusive'), ham.length) },
    failed: count(rs, (r) => r.cls === 'failed'),
    confusion,
    byConfidence,
    benignHigh: {
      shareOfLegitimatePct: benignHighHam,
      shareOfPhishingPct: benignHighPhish,
      note: 'precision of "benign, high" if phishing made up 1% / 10% of the input (derived from the two rates above)',
      precisionAtPrevalence1Pct: atPrevalence(0.01),
      precisionAtPrevalence10Pct: atPrevalence(0.1),
    },
  };
}

const result = {
  generatedAt: new Date().toISOString(),
  engine: ENGINE_VERSION,
  thresholds: DEFAULT_THRESHOLDS,
  note: 'Engine heuristics were developed with access to these corpora; the content-hash split guards against threshold tuning on the holdout, not against design-time exposure. See VALIDATION.md.',
  blockedSamples: corpusStats.blocked,
  seconds: Math.round((Date.now() - t0) / 1000),
  all: metrics(rows),
  tune: metrics(rows.filter((r) => r.split === 'tune')),
  holdout: metrics(rows.filter((r) => r.split === 'holdout')),
  perDataset: Object.fromEntries([...new Set(rows.map((r) => r.dataset))].map((d) => [d, metrics(rows.filter((r) => r.dataset === d))])),
};
mkdirSync(dirname(outPath), { recursive: true });
writeFileSync(outPath, JSON.stringify(result, null, 2));
console.log(JSON.stringify({ all: result.all, holdout: result.holdout, seconds: result.seconds, blocked: result.blockedSamples }, null, 2));
console.log(`→ ${outPath}`);
