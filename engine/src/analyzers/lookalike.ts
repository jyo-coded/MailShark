// Lookalike-domain detection: typosquats, homoglyph/confusable swaps, and brand-embedding
// ("paypal-secure.com", "microsoft.com.verify-login.ru").
import { BRAND_DOMAINS, type Brand, isBrandDomain } from '../data/brands';
import { hostInfo, toUnicodeHost } from '../util/domain';
import { levenshtein } from '../util/text';

// Confusables folded to their ASCII skeleton (subset of Unicode TR39 most used in phishing).
const CONFUSABLES: Record<string, string> = {
  а: 'a', е: 'e', о: 'o', р: 'p', с: 'c', у: 'y', х: 'x', і: 'i', ј: 'j', ԁ: 'd', ɡ: 'g', һ: 'h', ӏ: 'l', ѕ: 's', ԛ: 'q', ԝ: 'w',
  ο: 'o', α: 'a', ν: 'v', ι: 'i', κ: 'k', τ: 't', ρ: 'p', υ: 'u', β: 'b', ε: 'e', η: 'n', χ: 'x', μ: 'u',
  'ı': 'i', 'ł': 'l', 'ø': 'o', 'ö': 'o', 'ó': 'o', 'ò': 'o', 'ô': 'o', 'õ': 'o', 'á': 'a', 'à': 'a', 'â': 'a', 'ä': 'a', 'ã': 'a', 'å': 'a',
  'é': 'e', 'è': 'e', 'ê': 'e', 'ë': 'e', 'í': 'i', 'ì': 'i', 'î': 'i', 'ï': 'i', 'ú': 'u', 'ù': 'u', 'û': 'u', 'ü': 'u', 'ç': 'c', 'ñ': 'n',
  'ý': 'y', 'ÿ': 'y', 'ś': 's', 'ş': 's', 'ž': 'z', 'ż': 'z', 'ź': 'z', 'ğ': 'g', 'ċ': 'c', 'ḿ': 'm',
};

/** ASCII skeleton of a label, collapsing visual tricks like rn→m, vv→w, 0→o, 1/l→l. */
export function skeleton(label: string): string {
  let s = '';
  for (const ch of label.toLowerCase()) s += CONFUSABLES[ch] ?? ch;
  return s
    .replace(/rn/g, 'm')
    .replace(/vv/g, 'w')
    .replace(/cl/g, 'd')
    .replace(/0/g, 'o')
    .replace(/[1|!]/g, 'l')
    .replace(/i/g, 'l')
    .replace(/5/g, 's')
    .replace(/3/g, 'e')
    .replace(/4/g, 'a')
    .replace(/8/g, 'b')
    .replace(/-/g, '');
}

export interface LookalikeHit {
  brand: Brand;
  target: string; // legitimate domain being imitated
  kind: 'homoglyph' | 'typosquat' | 'embedded' | 'subdomain';
}

const MIN_LABEL = 4;
// Labels that are ordinary words or common substrings of unrelated names ("shagmail" ⊃ "gmail").
const GENERIC_LABELS = new Set([
  'mail', 'email', 'login', 'secure', 'account', 'online', 'support', 'service', 'office', 'cloud', 'store', 'shop', 'app', 'apps',
  'news', 'info', 'bank', 'pay', 'post', 'live', 'www', 'web', 'home', 'help', 'meta', 'visa', 'chase', 'steam', 'apple', 'slack',
  'jio', 'stripe', 'indeed', 'upi', 'tcs', 'epfo', 'gmail', 'googlemail', 'hotmail', 'msn', 'windows', 'xbox', 'force',
  'booking', 'target', 'citizens', 'discover', 'regions', 'united', 'national', 'ally',
]);

export function detectLookalike(hostRaw: string): LookalikeHit | null {
  const info = hostInfo(hostRaw);
  if (info.isIp || !info.regDomain) return null;
  const unicode = toUnicodeHost(info.host) ?? info.host;
  const uInfo = hostInfo(unicode);
  const regDomain = info.regDomain;
  const label = (uInfo.regDomain ?? regDomain).split('.')[0] ?? '';
  const asciiLabel = regDomain.split('.')[0] ?? '';

  // Legit brand domains are never lookalikes of themselves.
  for (const bd of BRAND_DOMAINS) if (isBrandDomain(bd.brand, regDomain)) return null;

  const labelSkel = skeleton(label);
  for (const bd of BRAND_DOMAINS) {
    const target = bd.label;
    if (target.length < MIN_LABEL) continue;
    const targetSkel = skeleton(target);
    // 1) Homoglyph: different spelling, identical skeleton (pаypal with Cyrillic а, paypa1, rnicrosoft).
    if (label !== target && labelSkel === targetSkel) return { brand: bd.brand, target: bd.domain, kind: 'homoglyph' };
    // 2) Typosquat: 1–2 edits away on a long enough label.
    // Squatters keep the first letter so the name still "reads" right; requiring it avoids
    // flagging unrelated dictionary words that happen to be one edit away (tomato ≠ zomato).
    if (target.length >= 6 && asciiLabel !== target && asciiLabel[0] === target[0]) {
      const d = levenshtein(asciiLabel, target, 2);
      if (d > 0 && d <= (target.length >= 9 ? 2 : 1)) return { brand: bd.brand, target: bd.domain, kind: 'typosquat' };
    }
  }

  // 3) Brand embedded in the registrable label: "paypal-security", "securemicrosoft", "amazonsupport".
  for (const bd of BRAND_DOMAINS) {
    const target = bd.label;
    if (target.length < 5 || GENERIC_LABELS.has(target)) continue;
    if (asciiLabel === target || asciiLabel.length > target.length + 20) continue;
    // Plain embedding ("paypal-security") or embedding a disguised spelling ("paypa1-secure").
    if (asciiLabel.includes(target) || (labelSkel !== skeleton(target) && labelSkel.includes(skeleton(target)))) {
      return { brand: bd.brand, target: bd.domain, kind: 'embedded' };
    }
  }

  // 4) Brand domain used as a subdomain of an unrelated domain: "paypal.com.account-check.ru".
  const sub = info.subdomain;
  if (sub) {
    for (const bd of BRAND_DOMAINS) {
      if (bd.label.length < 4 || GENERIC_LABELS.has(bd.label)) continue;
      const parts = sub.split('.');
      if (parts.includes(bd.label) || sub.includes(bd.domain)) return { brand: bd.brand, target: bd.domain, kind: 'subdomain' };
    }
  }
  return null;
}
