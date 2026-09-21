// Accuracy harness: runs the shipping engine over labelled corpora and reports detection metrics.
//   node scripts/eval/run.mjs [--limit N] [--out lab/out/engine-eval.jsonl]
// Corpora (not committed; see lab/README.md): datasets/nazario (phishing, CC BY 4.0),
// datasets/phishing_pot/email (phishing), datasets/spamassassin/{easy_ham,easy_ham_2,hard_ham} (legitimate).
import { createWriteStream, existsSync, mkdirSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { analyzeEmail } from '../../engine/src/analyze';
import { BloomFilter, BloomIntel } from '../../engine/src/intel/bloom';

interface Sample {
  dataset: string;
  group: string;
  label: 'phish' | 'ham';
  name: string;
  raw: Uint8Array;
}

const args = process.argv.slice(2);
const limit = Number(args[args.indexOf('--limit') + 1] || 0) || Infinity;
const outPath = args.includes('--out') ? (args[args.indexOf('--out') + 1] as string) : 'lab/out/engine-eval.jsonl';
const root = process.cwd();
const intelDir = args.includes('--intel') ? (args[args.indexOf('--intel') + 1] as string) : null;
const only = args.includes('--only') ? (args[args.indexOf('--only') + 1] as string) : null;
function loadIntel(): BloomIntel | null {
  if (!intelDir) return null;
  const man = JSON.parse(readFileSync(join(intelDir, 'manifest.json'), 'utf8')) as { lists: { name: string; file: string; m: number; k: number; count: number }[] };
  return new BloomIntel(man.lists.map((l) => new BloomFilter({ name: l.name, m: l.m, k: l.k, count: l.count }, new Uint8Array(readFileSync(join(intelDir, l.file))))));
}
let blocked = 0;

function* mbox(path: string): Generator<Uint8Array> {
  const buf = readFileSync(path);
  const text = buf.toString('latin1');
  const starts: number[] = [];
  const re = /(^|\n)From [^\n]*\n/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text))) starts.push(m.index + m[1]!.length);
  for (let i = 0; i < starts.length; i++) {
    const s = starts[i] as number;
    const bodyStart = text.indexOf('\n', s) + 1;
    const end = i + 1 < starts.length ? (starts[i + 1] as number) : text.length;
    const msg = text.slice(bodyStart, end).replace(/\n>From /g, '\nFrom ');
    yield Buffer.from(msg, 'latin1');
  }
}

function* samples(): Generator<Sample> {
  const naz = join(root, 'datasets', 'nazario');
  if (existsSync(naz)) {
    for (const f of readdirSync(naz).filter((x) => /^phishing-\d{4}$/.test(x)).sort()) {
      let n = 0;
      for (const raw of mbox(join(naz, f))) {
        if (n++ >= limit) break;
        yield { dataset: 'nazario', group: f.slice(-4), label: 'phish', name: `${f}#${n}`, raw };
      }
    }
  }
  const pot = join(root, 'datasets', 'phishing_pot', 'email');
  if (existsSync(pot)) {
    let n = 0;
    for (const f of readdirSync(pot).filter((x) => x.endsWith('.eml')).sort()) {
      if (n++ >= limit) break;
      let raw: Uint8Array;
      try {
        raw = readFileSync(join(pot, f));
      } catch {
        blocked++; // e.g. quarantined by antivirus: the sample carries live malware
        continue;
      }
      yield { dataset: 'phishing_pot', group: 'pot', label: 'phish', name: f, raw };
    }
  }
  const sa = join(root, 'datasets', 'spamassassin');
  for (const d of ['easy_ham', 'easy_ham_2', 'hard_ham']) {
    const dir = join(sa, d);
    if (!existsSync(dir)) continue;
    let n = 0;
    for (const f of readdirSync(dir).sort()) {
      if (f === 'cmds' || statSync(join(dir, f)).isDirectory()) continue;
      if (n++ >= limit) break;
      let raw = readFileSync(join(dir, f));
      // Strip the mbox envelope line some SpamAssassin files start with.
      if (raw.subarray(0, 5).toString('latin1') === 'From ') raw = raw.subarray(raw.indexOf(10) + 1);
      yield { dataset: 'spamassassin', group: d, label: 'ham', name: f, raw };
    }
  }
}

async function main(): Promise<void> {
  mkdirSync(dirname(outPath), { recursive: true });
  const out = createWriteStream(outPath);
  const agg = new Map<string, { n: number; danger: number; caution: number; safe: number; errors: number }>();
  const fpFindings = new Map<string, number>();
  const fnReasons = new Map<string, number>();
  let n = 0;
  const t0 = Date.now();
  const intel = loadIntel();
  for (const s of samples()) {
    if (only && s.dataset !== only) continue;
    const key = `${s.dataset}/${s.group}`;
    const a = agg.get(key) ?? { n: 0, danger: 0, caution: 0, safe: 0, errors: 0 };
    a.n++;
    try {
      const r = await analyzeEmail(s.raw, { now: new Date('2026-09-21T00:00:00Z'), intel });
      a[r.verdict]++;
      const positives = r.findings.filter((f) => f.weight > 0).map((f) => f.id.replace(/:.*$/, ''));
      if (s.label === 'ham' && r.verdict !== 'safe') for (const id of positives) fpFindings.set(id, (fpFindings.get(id) ?? 0) + 1);
      if (s.label === 'phish' && r.verdict === 'safe') fnReasons.set(r.content.intent ?? (r.auth.source === 'none' ? 'no-auth-no-intent' : 'no-intent'), (fnReasons.get(r.content.intent ?? (r.auth.source === 'none' ? 'no-auth-no-intent' : 'no-intent')) ?? 0) + 1);
      out.write(
        JSON.stringify({
          dataset: s.dataset, group: s.group, label: s.label, name: s.name, score: r.score, verdict: r.verdict, confidence: r.confidence,
          subject: r.summary.subject.slice(0, 90), from: r.summary.from ? `${r.summary.from.name} <${r.summary.from.address}>` : null, brands: r.content.brandMentions, claimed: r.sender.claimedBrands,
          findings: r.findings.map((f) => [f.id.replace(/:.*$/, ''), f.weight]), intent: r.content.intent, urgency: r.content.urgency,
          auth: [r.auth.source, r.auth.spf, r.auth.dkim, r.auth.dmarc], links: r.links.length, riskyLinks: r.links.filter((l) => l.risk >= 2).length,
          attachments: r.attachments.length, ms: r.timings['total'],
          linkFlags: r.links.filter((l) => l.risk >= 1).slice(0, 6).map((l) => [l.host, l.flags.join(' '), l.lookalikeOf]), preview: r.content.textPreview.slice(0, 160),
        }) + '\n',
      );
    } catch (e) {
      a.errors++;
      out.write(JSON.stringify({ dataset: s.dataset, group: s.group, label: s.label, name: s.name, error: String(e) }) + '\n');
    }
    agg.set(key, a);
    if (++n % 500 === 0) process.stderr.write(`  ${n} messages (${Math.round((Date.now() - t0) / 1000)}s)\n`);
  }
  out.end();

  const pct = (x: number, d: number): string => (d ? ((100 * x) / d).toFixed(1) + '%' : '—');
  console.log('\nPer corpus (flagged = danger + caution):');
  let pN = 0, pHit = 0, pDanger = 0, hN = 0, hFlag = 0, hDanger = 0;
  for (const [key, a] of [...agg.entries()].sort()) {
    const isHam = key.startsWith('spamassassin');
    const flagged = a.danger + a.caution;
    console.log(`  ${key.padEnd(26)} n=${String(a.n).padStart(5)}  danger ${pct(a.danger, a.n).padStart(6)}  caution ${pct(a.caution, a.n).padStart(6)}  ${isHam ? 'FALSE-POS' : 'detected '} ${pct(flagged, a.n).padStart(6)}  errors ${a.errors}`);
    if (isHam) { hN += a.n; hFlag += flagged; hDanger += a.danger; } else { pN += a.n; pHit += flagged; pDanger += a.danger; }
  }
  const tp = pHit, fn = pN - pHit, fp = hFlag, tn = hN - hFlag;
  const precision = tp / Math.max(1, tp + fp);
  const recall = tp / Math.max(1, tp + fn);
  console.log('\nOverall');
  console.log(`  phishing detected (recall)     ${pct(pHit, pN)}  (${pHit}/${pN}); rated dangerous ${pct(pDanger, pN)}`);
  console.log(`  legitimate flagged (FPR)       ${pct(hFlag, hN)}  (${hFlag}/${hN}); rated dangerous ${pct(hDanger, hN)}`);
  console.log(`  precision ${(precision * 100).toFixed(1)}%   F1 ${((2 * precision * recall) / Math.max(1e-9, precision + recall) * 100).toFixed(1)}%   (class-balanced: see lab report)`);
  if (blocked) console.log(`  ${blocked} samples unreadable (blocked by antivirus) were skipped`);
  console.log(`  ${n} messages in ${Math.round((Date.now() - t0) / 1000)}s → ${outPath}`);
  console.log('\nFindings behind false positives:', [...fpFindings.entries()].sort((a, b) => b[1] - a[1]).slice(0, 12));
  console.log('Missed phishing by primary intent:', [...fnReasons.entries()].sort((a, b) => b[1] - a[1]).slice(0, 10));
}

void main();
