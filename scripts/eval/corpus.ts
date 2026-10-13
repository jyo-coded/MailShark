// Labelled evaluation corpora (not committed; see lab/README.md and docs/platform/VALIDATION.md):
//   datasets/nazario/phishing-YYYY         phishing, mbox (Jose Nazario, CC BY 4.0)
//   datasets/phishing_pot/email/*.eml       phishing collected by honeypots (rf-peixoto/phishing_pot)
//   datasets/spamassassin/{easy_ham,…}      legitimate mail (SpamAssassin public corpus, 2002–2003)
import { createHash } from 'node:crypto';
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';

export interface Sample {
  dataset: string;
  group: string;
  label: 'phish' | 'ham';
  name: string;
  raw: Uint8Array;
}

export const corpusStats = { blocked: 0 };

export function* mbox(path: string): Generator<Uint8Array> {
  const text = readFileSync(path).toString('latin1');
  const starts: number[] = [];
  const re = /(^|\n)From [^\n]*\n/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text))) starts.push(m.index + (m[1] as string).length);
  for (let i = 0; i < starts.length; i++) {
    const s = starts[i] as number;
    const bodyStart = text.indexOf('\n', s) + 1;
    const end = i + 1 < starts.length ? (starts[i + 1] as number) : text.length;
    yield Buffer.from(text.slice(bodyStart, end).replace(/\n>From /g, '\nFrom '), 'latin1');
  }
}

export function* samples(root: string, limit = Infinity): Generator<Sample> {
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
        corpusStats.blocked++; // e.g. quarantined by antivirus: the sample carries live malware
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

/**
 * Deterministic split from the message bytes (SHA-256): "tune" (≈70%) or "holdout" (≈30%).
 * Content-based, so the same message always lands in the same split, whatever the file order.
 */
export function splitOf(raw: Uint8Array): 'tune' | 'holdout' {
  const h = createHash('sha256').update(raw).digest();
  return (h[0] as number) < 179 ? 'tune' : 'holdout';
}
