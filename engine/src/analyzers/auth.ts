// SPF / DKIM / DMARC / ARC evaluation. We only trust Authentication-Results written by the
// receiving provider: attackers can insert their own fake "dkim=pass" headers further down.
import type { AuthAnalysis, AuthMethodResult, AuthResult, DkimSignature } from '../types';
import { orgDomain } from '../util/domain';
import { collapseWs } from '../util/text';

const RESULTS: AuthResult[] = ['pass', 'fail', 'softfail', 'neutral', 'none', 'temperror', 'permerror', 'policy', 'bestguesspass'];

function normResult(r: string | undefined): AuthResult {
  const v = (r ?? '').toLowerCase();
  if (v === 'hardfail') return 'fail';
  return (RESULTS as string[]).includes(v) ? (v as AuthResult) : 'unknown';
}

/** Split on ';' that are not inside parentheses or quotes. */
function splitClauses(s: string): string[] {
  const out: string[] = [];
  let depth = 0;
  let quoted = false;
  let cur = '';
  for (const ch of s) {
    if (ch === '"') quoted = !quoted;
    else if (!quoted && ch === '(') depth++;
    else if (!quoted && ch === ')') depth = Math.max(0, depth - 1);
    if (ch === ';' && depth === 0 && !quoted) {
      out.push(cur);
      cur = '';
    } else cur += ch;
  }
  if (cur.trim()) out.push(cur);
  return out.map((c) => c.trim()).filter(Boolean);
}

export interface ParsedAuthResults {
  authServId: string;
  results: AuthMethodResult[];
}

export function parseAuthResults(value: string): ParsedAuthResults {
  const clauses = splitClauses(collapseWs(value));
  let authServId = '';
  const results: AuthMethodResult[] = [];
  clauses.forEach((clause, idx) => {
    const m = /^([a-z][a-z0-9._-]*)\s*=\s*([a-z]+)/i.exec(clause);
    if (idx === 0 && !m) {
      authServId = clause.split(/\s+/)[0]?.toLowerCase() ?? '';
      return;
    }
    if (idx === 0 && m && /^i$/i.test(m[1] ?? '')) return; // ARC "i=1" instance tag
    if (!m) {
      if (!authServId) authServId = clause.split(/\s+/)[0]?.toLowerCase() ?? '';
      return;
    }
    const method = (m[1] as string).toLowerCase();
    if (method === 'i') return;
    const comment = /\(([^)]*)\)/.exec(clause)?.[1] ?? null;
    const props: Record<string, string> = {};
    const stripped = clause.replace(/\([^)]*\)/g, ' ');
    for (const pm of stripped.matchAll(/\b([a-z]+(?:\.[a-z-]+)?)\s*=\s*("[^"]*"|[^\s;]+)/gi)) {
      const k = (pm[1] as string).toLowerCase();
      if (k === method) continue;
      props[k] = (pm[2] as string).replace(/^"|"$/g, '');
    }
    results.push({ method, result: normResult(m[2]), props, comment });
  });
  // ARC-Authentication-Results carry "i=N; authserv-id; …": authserv-id is the 2nd clause.
  if (!authServId && clauses.length > 1 && /^i\s*=/i.test(clauses[0] ?? '')) authServId = (clauses[1] ?? '').split(/\s+/)[0]?.toLowerCase() ?? '';
  return { authServId, results };
}

export function parseDkimSignature(value: string): DkimSignature | null {
  const tags: Record<string, string> = {};
  for (const part of collapseWs(value).split(';')) {
    const i = part.indexOf('=');
    if (i < 0) continue;
    tags[part.slice(0, i).trim().toLowerCase()] = part.slice(i + 1).replace(/\s+/g, '').trim();
  }
  if (!tags['d']) return null;
  return {
    domain: tags['d'].toLowerCase(),
    selector: (tags['s'] ?? '').toLowerCase(),
    algorithm: (tags['a'] ?? '').toLowerCase(),
    signedHeaders: (tags['h'] ?? '')
      .toLowerCase()
      .split(':')
      .map((h) => h.trim())
      .filter(Boolean),
  };
}

export interface AuthInputs {
  authResults: string[]; // top → bottom
  arcAuthResults: string[];
  receivedSpf: string[];
  dkimSignatures: string[];
  receiverOrg: string | null;
  fromDomain: string | null;
}

function worst(results: AuthMethodResult[], method: string): { result: AuthResult; entry: AuthMethodResult | null } {
  const list = results.filter((r) => r.method === method);
  if (!list.length) return { result: 'none', entry: null };
  const order: AuthResult[] = ['pass', 'bestguesspass', 'neutral', 'none', 'policy', 'softfail', 'temperror', 'permerror', 'fail', 'unknown'];
  // For DKIM, any passing signature counts as pass (multiple signatures are normal).
  if (method === 'dkim') {
    const pass = list.find((r) => r.result === 'pass');
    if (pass) return { result: 'pass', entry: pass };
  }
  let best = list[0] as AuthMethodResult;
  for (const r of list) if (order.indexOf(r.result) > order.indexOf(best.result)) best = r;
  return { result: best.result, entry: best };
}

export function analyzeAuth(input: AuthInputs): AuthAnalysis {
  const signatures = input.dkimSignatures.map(parseDkimSignature).filter((s): s is DkimSignature => !!s);
  const parsed = input.authResults.map(parseAuthResults);

  let chosen: ParsedAuthResults | null = null;
  let source: AuthAnalysis['source'] = 'none';
  if (parsed.length) {
    if (input.receiverOrg) {
      chosen = parsed.find((p) => p.authServId && orgDomain(p.authServId) === input.receiverOrg) ?? null;
      if (!chosen && ['outlook.com', 'office365.com', 'microsoft.com', 'hotmail.com'].includes(input.receiverOrg)) {
        // Exchange Online omits the authserv-id; its own header is always the top-most one.
        chosen =
          parsed.find((p) => /outlook\.com|microsoft\.com|office365\.com/.test(p.authServId)) ??
          (parsed[0]?.authServId === '' ? (parsed[0] as ParsedAuthResults) : null);
      }
    }
    if (chosen) source = 'trusted';
    else {
      chosen = parsed[0] as ParsedAuthResults;
      source = 'topmost';
    }
  }
  // Received-SPF (written by the receiving MTA) as a fallback SPF source.
  const results = chosen ? [...chosen.results] : [];
  if (!results.some((r) => r.method === 'spf') && input.receivedSpf.length) {
    const m = /^\s*([a-z]+)/i.exec(input.receivedSpf[0] as string);
    if (m) results.push({ method: 'spf', result: normResult(m[1]), props: {}, comment: collapseWs(input.receivedSpf[0] as string) });
  }
  let arc: AuthResult = worst(results, 'arc').result;
  if (arc === 'none' && input.arcAuthResults.length) {
    const top = parseAuthResults(input.arcAuthResults[0] as string);
    arc = worst(top.results, 'arc').result;
  }

  const spf = worst(results, 'spf');
  const dkim = worst(results, 'dkim');
  const dmarc = worst(results, 'dmarc');
  const compauthList = results.filter((r) => r.method === 'compauth');
  const dkimDomains = results
    .filter((r) => r.method === 'dkim' && r.result === 'pass')
    .map((r) => (r.props['header.d'] ?? r.props['header.i']?.replace(/^.*@/, '') ?? '').toLowerCase())
    .filter(Boolean);

  const spfDomain = (spf.entry?.props['smtp.mailfrom'] ?? spf.entry?.props['smtp.helo'] ?? '').replace(/^.*@/, '').toLowerCase() || null;
  const headerFrom = (dmarc.entry?.props['header.from'] ?? input.fromDomain ?? '').toLowerCase() || null;
  const fromOrg = orgDomain(headerFrom ?? input.fromDomain ?? '');

  const spfAligned = spf.result === 'pass' && spfDomain ? orgDomain(spfDomain) === fromOrg : spf.result === 'none' ? null : false;
  const dkimAligned = dkimDomains.length ? dkimDomains.some((d) => orgDomain(d) === fromOrg) : dkim.result === 'none' ? null : false;
  const policyRaw = dmarc.entry?.comment ?? '';
  const dmarcPolicy = /\bp=([a-z]+)/i.exec(policyRaw)?.[1]?.toLowerCase() ?? dmarc.entry?.props['policy.dmarc'] ?? null;

  return {
    source,
    authServId: chosen?.authServId ?? null,
    spf: spf.result,
    dkim: dkim.result,
    dmarc: dmarc.result,
    arc,
    compauth: compauthList.length ? (compauthList[0] as AuthMethodResult).result : null,
    dmarcPolicy,
    spfDomain,
    dkimDomains: [...new Set(dkimDomains)],
    headerFrom,
    spfAligned,
    dkimAligned,
    signatures,
    results,
  };
}
