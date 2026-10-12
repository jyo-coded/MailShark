// Evidence coverage: which layers of the message were actually present and inspectable.
// Absence of evidence is not evidence of absence: a message with no Authentication-Results, an
// image-only body or an encrypted archive cannot be called benign with the same confidence as one
// where every layer was examined. Coverage feeds the "inconclusive" class and the confidence rule.
import type { AttachmentAnalysis, AuthAnalysis, CoverageLayer, EvidenceCoverage, HtmlAnalysis, LinkAnalysis, RouteAnalysis, StructureAnalysis } from './types';

export interface CoverageInputs {
  headerCount: number;
  hasFrom: boolean;
  malformedHeaderLines: number;
  route: RouteAnalysis;
  auth: AuthAnalysis;
  dkimBodyVerified: boolean;
  bodyTextChars: number;
  html: HtmlAnalysis;
  structure: StructureAnalysis;
  links: LinkAnalysis[];
  attachments: AttachmentAnalysis[];
}

const STATUS_VALUE = { available: 1, partial: 0.5, absent: 0, 'not-applicable': 0 } as const;

const ENCRYPTED_TYPES = /^(multipart\/encrypted|application\/(x-)?pkcs7-mime|application\/pgp-encrypted)$/;
const UNINSPECTABLE = ['encrypted-archive', 'encrypted-office', 'uninspectable-archive', 'not-inspected-size'];

export function assessCoverage(x: CoverageInputs): EvidenceCoverage {
  const layers: CoverageLayer[] = [];

  layers.push(
    x.headerCount >= 4 && x.hasFrom
      ? { id: 'headers', label: 'Header block', status: x.malformedHeaderLines > 2 ? 'partial' : 'available', weight: 0.15, note: x.malformedHeaderLines > 2 ? `${x.malformedHeaderLines} malformed header lines were skipped.` : `${x.headerCount} header fields parsed.` }
      : { id: 'headers', label: 'Header block', status: x.headerCount ? 'partial' : 'absent', weight: 0.15, note: x.hasFrom ? 'Very few header fields: the message may be truncated or re-typed.' : 'No usable From header.' },
  );

  const trusted = x.route.hops.filter((h) => h.trusted).length;
  layers.push(
    !x.route.hops.length
      ? { id: 'route', label: 'Delivery path (Received)', status: 'absent', weight: 0.15, note: 'No Received headers: the delivery path cannot be reconstructed (draft, re-saved or stripped copy).' }
      : trusted
        ? { id: 'route', label: 'Delivery path (Received)', status: 'available', weight: 0.15, note: `${x.route.hops.length} hops; hand-off to the receiving organisation identified.` }
        : { id: 'route', label: 'Delivery path (Received)', status: 'partial', weight: 0.15, note: `${x.route.hops.length} hops, but none could be attributed to the receiving organisation; all are unverified.` },
  );

  const authLayer: CoverageLayer =
    x.auth.source === 'trusted'
      ? { id: 'authentication', label: 'Sender authentication', status: 'available', weight: 0.15, note: `SPF/DKIM/DMARC results written by ${x.auth.authServId ?? 'the receiving server'}.` }
      : x.auth.source === 'topmost'
        ? { id: 'authentication', label: 'Sender authentication', status: 'partial', weight: 0.15, note: 'Authentication results are present but could not be attributed to the receiving server; they are treated as unverified.' }
        : x.dkimBodyVerified
          ? { id: 'authentication', label: 'Sender authentication', status: 'partial', weight: 0.15, note: 'No receiver verdicts in this copy; a DKIM body hash was verified offline.' }
          : { id: 'authentication', label: 'Sender authentication', status: 'absent', weight: 0.15, note: 'No SPF/DKIM/DMARC results in this copy of the message. This is unavailable evidence, not a failure.' };
  layers.push(authLayer);

  const encrypted = x.structure.parts.some((p) => ENCRYPTED_TYPES.test(p.contentType));
  layers.push(
    encrypted
      ? { id: 'body', label: 'Message body', status: 'absent', weight: 0.25, note: 'The body is encrypted (S/MIME or PGP) and cannot be inspected.' }
      : x.bodyTextChars >= 40
        ? { id: 'body', label: 'Message body', status: x.html.imageOnly ? 'partial' : 'available', weight: 0.25, note: x.html.imageOnly ? 'The visible message is mostly an image; its text was not analysed (no OCR).' : `${x.bodyTextChars.toLocaleString('en')} characters of text analysed.` }
        : { id: 'body', label: 'Message body', status: x.html.images > 0 ? 'partial' : 'absent', weight: 0.25, note: x.html.images > 0 ? 'Image-only body: text inside images was not analysed (no OCR).' : 'Little or no body text.' },
  );

  layers.push(
    x.links.length
      ? { id: 'links', label: 'Links', status: 'available', weight: 0.15, note: `${x.links.length} links extracted and analysed (not visited).` }
      : { id: 'links', label: 'Links', status: 'not-applicable', weight: 0.15, note: 'No links in the message.' },
  );

  const atts = x.attachments.filter((a) => !a.inline || a.risk > 0);
  const blind = atts.filter((a) => a.flags.some((f) => UNINSPECTABLE.includes(f)));
  layers.push(
    !atts.length
      ? { id: 'attachments', label: 'Attachments', status: 'not-applicable', weight: 0.2, note: 'No attachments.' }
      : blind.length
        ? { id: 'attachments', label: 'Attachments', status: blind.length === atts.length ? 'absent' : 'partial', weight: 0.2, note: `${blind.length} of ${atts.length} attachments could not be inspected (encrypted, unsupported archive format or too large).` }
        : { id: 'attachments', label: 'Attachments', status: 'available', weight: 0.2, note: `${atts.length} attachments inspected statically (not opened or executed).` },
  );

  let num = 0;
  let den = 0;
  for (const l of layers) {
    if (l.status === 'not-applicable') continue;
    num += l.weight * STATUS_VALUE[l.status];
    den += l.weight;
  }
  return { score: den ? Math.round((num / den) * 100) / 100 : 0, layers };
}
