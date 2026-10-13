// Stage-level timing profile of the engine over a sample of corpus messages.
//   node scripts/eval/run-profile.mjs [--limit N]
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { analyzeEmail } from '../../engine/src/analyze';

const args = process.argv.slice(2);
const limit = Number(args[args.indexOf('--limit') + 1] || 0) || 300;
const dir = join(process.cwd(), 'datasets', 'phishing_pot', 'email');
const files = readdirSync(dir).filter((f) => f.endsWith('.eml')).sort().slice(0, limit);
const totals: Record<string, number[]> = {};
for (const f of files) {
  let raw: Buffer;
  try {
    raw = readFileSync(join(dir, f));
  } catch {
    continue;
  }
  const r = await analyzeEmail(new Uint8Array(raw));
  for (const [k, v] of Object.entries(r.timings)) (totals[k] ??= []).push(v);
}
const q = (a: number[], p: number): number => [...a].sort((x, y) => x - y)[Math.floor(a.length * p)] ?? 0;
for (const [k, v] of Object.entries(totals).sort((a, b) => b[1].reduce((s, x) => s + x, 0) - a[1].reduce((s, x) => s + x, 0))) {
  console.log(`${k.padEnd(12)} sum ${v.reduce((s, x) => s + x, 0).toFixed(0).padStart(7)} ms   median ${q(v, 0.5).toFixed(1).padStart(6)}   p95 ${q(v, 0.95).toFixed(1).padStart(7)}`);
}
