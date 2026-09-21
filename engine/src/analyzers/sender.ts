// Sender identity: who the message claims to be from vs. who provably sent it.
import { addressParser } from 'postal-mime';
import type { AddressInfo, AuthAnalysis, SenderAnalysis } from '../types';
import { findBrands, isBrandDomain, type Brand } from '../data/brands';
import { domainOfAddress, isFreemail, orgDomain } from '../util/domain';
import { decodeHeaderValue } from '../mime/raw';
import { detectLookalike } from './lookalike';

export function toAddressInfo(name: string, address: string): AddressInfo {
  const addr = address.trim().toLowerCase();
  const domain = domainOfAddress(addr);
  return { name: name.trim(), address: addr, domain, orgDomain: orgDomain(domain) };
}

export function parseAddressList(raw: string | null | undefined): AddressInfo[] {
  if (!raw) return [];
  try {
    const decoded = decodeHeaderValue(raw);
    const list = addressParser(decoded, { flatten: true });
    return list
      .filter((a): a is { name: string; address: string } => typeof (a as { address?: string }).address === 'string')
      .map((a) => toAddressInfo(a.name ?? '', a.address));
  } catch {
    return [];
  }
}

export interface SenderInputs {
  fromRaw: string | null;
  replyToRaw: string | null;
  returnPathRaw: string | null;
  senderRaw: string | null;
  auth: AuthAnalysis;
  subject: string;
  senderSeenCount: number | null | undefined;
}

export function analyzeSender(input: SenderInputs): SenderAnalysis & { claimed: Brand[] } {
  const from = parseAddressList(input.fromRaw)[0] ?? null;
  const replyTo = parseAddressList(input.replyToRaw);
  const returnPath = parseAddressList(input.returnPathRaw)[0] ?? null;
  const sender = parseAddressList(input.senderRaw)[0] ?? null;

  // Display name containing an e-mail address of another domain: "support@paypal.com" <x@evil.tld>
  let displayNameAddress: string | null = null;
  if (from?.name) {
    const m = /[\w.+-]+@([\w-]+\.)+[\w-]{2,}/.exec(from.name);
    if (m && orgDomain(domainOfAddress(m[0])) !== from.orgDomain) displayNameAddress = m[0].toLowerCase();
  }

  // Identity claims come from the display name and the mailbox name only. Brands merely mentioned
  // in the subject/body are weighed later together with the message's intent.
  const claimSource = [from?.name ?? '', from ? from.address.split('@')[0]?.replace(/[._-]+/g, ' ') ?? '' : '', displayNameAddress ?? ''].join(' ');
  const claimed = findBrands(claimSource, true);

  const freemail = from ? isFreemail(from.domain) : false;
  const dkimOrgs = input.auth.dkimDomains.map((d) => orgDomain(d));
  const fromIsBrand = (brand: Brand): boolean =>
    !!from && !freemail && (isBrandDomain(brand, from.orgDomain) || isBrandDomain(brand, from.domain));
  const authenticatedAs = (brand: Brand): boolean => {
    if (!fromIsBrand(brand)) return false;
    const aligned = input.auth.dmarc === 'pass' || input.auth.dkimAligned === true || input.auth.spfAligned === true;
    // ESP sending on the brand's behalf signs with the brand's own domain.
    return aligned || dkimOrgs.some((d) => isBrandDomain(brand, d));
  };
  const spoofedDomain = input.auth.dmarc === 'fail' || (input.auth.spf === 'fail' && input.auth.dkim !== 'pass') || input.auth.compauth === 'fail';

  let verifiedBrand: string | null = null;
  let impersonatedBrand: string | null = null;
  for (const b of claimed) {
    if (authenticatedAs(b)) verifiedBrand = verifiedBrand ?? b.id;
    else if (fromIsBrand(b)) {
      // The brand's real domain is in From but authentication failed: exact-domain spoofing.
      if (input.auth.source !== 'none' && spoofedDomain) impersonatedBrand = impersonatedBrand ?? b.id;
    } else impersonatedBrand = impersonatedBrand ?? b.id;
  }
  // A verified brand explains mentions of other brands (e.g. Google mail mentioning YouTube).
  if (verifiedBrand && impersonatedBrand) {
    const vb = claimed.find((b) => b.id === verifiedBrand);
    const ib = claimed.find((b) => b.id === impersonatedBrand);
    if (vb && ib && ib.domains.some((d) => vb.domains.includes(d))) impersonatedBrand = null;
  }

  const lookalike = from ? detectLookalike(from.domain) : null;

  return {
    from,
    replyTo,
    returnPath,
    sender,
    isFreemail: freemail,
    claimedBrands: claimed.map((b) => b.id),
    impersonatedBrand,
    verifiedBrand,
    lookalikeOf: lookalike ? `${lookalike.brand.name} (${lookalike.target})` : null,
    displayNameAddress,
    firstTimeSender: input.senderSeenCount == null ? null : input.senderSeenCount === 0,
    claimed,
  };
}
