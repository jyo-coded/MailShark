// Multi-layer campaign fingerprint: compact, privacy-preserving (hashes/templates, no body text)
// and designed around what attackers rarely rotate: templates, tooling, infrastructure habits.
import type { AttachmentAnalysis, AuthAnalysis, ContentAnalysis, EspInfo, Fingerprint, HtmlAnalysis, LinkAnalysis, RouteAnalysis, SenderAnalysis } from './types';
import type { RawHeader } from './mime/raw';
import { hash53, lshBandKeys, minhash, shingles, simhash } from './util/hash';
import { ipNetwork, orgDomain } from './util/domain';
import { tokenize } from './util/text';

// Headers added in transit by receivers; excluded so the order reflects the sending software only.
const TRANSIT_HEADER = /^(received|x-received|arc-|authentication-results|received-spf|delivered-to|return-path|x-google-|x-gm-|x-ms-|x-microsoft-|x-forefront-|x-eopattributedmessage|x-originating-ip|x-spam|x-virus|x-proofpoint|x-mimecast|x-apple-|x-yahoo|x-ymail|x-rocket|x-sonic|x-originatororg|x-crosspremises|x-mailshark)/;

export function headerOrderSignature(headers: RawHeader[]): string | null {
  const names = headers.map((h) => h.key).filter((k) => !TRANSIT_HEADER.test(k) && k !== 'dkim-signature');
  if (names.length < 3) return null;
  return hash53(names.join('>'));
}

export function messageIdTemplate(messageId: string | null): { template: string | null; domain: string | null } {
  if (!messageId) return { template: null, domain: null };
  const m = /<?([^<>@\s]+)@([^<>\s]+)>?/.exec(messageId);
  if (!m) return { template: null, domain: null };
  const local = (m[1] as string)
    .replace(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi, '{uuid}')
    .replace(/[A-Za-z0-9+/_-]{16,}={0,2}/g, '{tok}')
    .replace(/\d+/g, '{n}')
    .replace(/[a-f0-9]{6,}/gi, '{hex}');
  // The local-part layout is a property of the sending software; the domain is reported separately
  // because attackers rotate it.
  return { template: local, domain: orgDomain((m[2] as string).toLowerCase()) || (m[2] as string).toLowerCase() };
}

export function localPartTemplate(address: string | null | undefined): string | null {
  if (!address) return null;
  const local = address.split('@')[0] ?? '';
  return local
    .toLowerCase()
    .replace(/\d+/g, '{n}')
    .replace(/[a-z]{12,}/g, '{w}');
}

export interface FingerprintInputs {
  time: number;
  headers: RawHeader[];
  messageId: string | null;
  xMailer: string | null;
  sender: SenderAnalysis;
  auth: AuthAnalysis;
  route: RouteAnalysis;
  content: ContentAnalysis;
  html: HtmlAnalysis;
  bodyText: string;
  links: LinkAnalysis[];
  attachments: AttachmentAnalysis[];
  esp: EspInfo | null;
}

export function buildFingerprint(x: FingerprintInputs): Fingerprint {
  const tokens = tokenize(`${x.content.subject} ${x.bodyText.slice(0, 20_000)}`);
  const sh = shingles(tokens, 3);
  const sig = minhash(sh);
  const mid = messageIdTemplate(x.messageId);
  const signedHeaderSet = x.auth.signatures[0]?.signedHeaders.length ? hash53(x.auth.signatures[0].signedHeaders.join(':')) : null;
  const linkDomains = [...new Set(x.links.filter((l) => !l.flags.includes('unsubscribe') && l.regDomain).map((l) => l.regDomain as string))].sort();
  const linkTemplates = [...new Set(x.links.filter((l) => !l.flags.includes('tracking')).map((l) => l.template))].sort().slice(0, 40);
  const linkPaths = [
    ...new Set(
      x.links
        .filter((l) => !l.flags.includes('tracking') && !l.flags.includes('unsubscribe'))
        .map((l) => l.template.slice(l.template.indexOf('/')))
        .filter((p) => p.split('/').filter(Boolean).length >= 2),
    ),
  ]
    .sort()
    .slice(0, 40);
  const attachments = x.attachments.filter((a) => !(a.inline && ['png', 'jpeg', 'gif'].includes(a.detectedType) && a.size < 40_000));

  const fp: Fingerprint = {
    version: 1,
    time: x.time,
    sender: {
      fromDomain: x.sender.from?.domain ?? null,
      fromOrg: x.sender.from?.orgDomain ?? null,
      localTemplate: localPartTemplate(x.sender.from?.address),
      displayName: x.sender.from?.name ? x.sender.from.name.toLowerCase().replace(/\s+/g, ' ').trim() : null,
      replyToOrg: x.sender.replyTo[0]?.orgDomain ?? null,
      returnPathOrg: x.sender.returnPath?.orgDomain ?? null,
    },
    infra: {
      originIp: x.route.originIp,
      originNet: x.route.originIp ? ipNetwork(x.route.originIp) : null,
      originOrg: x.route.originOrg,
      xMailer: x.xMailer ? x.xMailer.toLowerCase().replace(/\d+(\.\d+)*/g, '{v}').slice(0, 80) : null,
      dkimDomains: [...new Set(x.auth.signatures.map((s) => orgDomain(s.domain)))].sort(),
      dkimSelectors: [...new Set(x.auth.signatures.map((s) => s.selector.replace(/\d+/g, '{n}')))].sort(),
      dkimHeaderSet: signedHeaderSet,
      headerOrder: headerOrderSignature(x.headers),
      messageIdTemplate: mid.template,
      messageIdDomain: mid.domain,
      esp: x.esp?.id ?? null,
      espCampaign: x.esp?.campaignId ? `${x.esp.id}:${x.esp.customerId ?? ''}:${x.esp.campaignId}` : null,
    },
    content: {
      subjectTemplate: x.content.subjectTemplate,
      subjectTokens: [...new Set(tokenize(x.content.subject))].slice(0, 24),
      minhash: sig,
      simhash: simhash(sh),
      skeleton: x.html.skeletonHash,
      classHash: x.html.classHash,
      intent: x.content.intent,
      brand: x.sender.impersonatedBrand ?? x.sender.verifiedBrand ?? x.content.brandMentions[0] ?? null,
      actions: x.content.requestedActions,
    },
    urls: { domains: linkDomains.slice(0, 40), templates: linkTemplates, paths: linkPaths },
    attachments: {
      sha256: attachments.map((a) => a.sha256),
      structural: [...new Set(attachments.map((a) => a.structural))],
      nameTemplates: [...new Set(attachments.map((a) => a.filename.toLowerCase().replace(/\d+/g, '#')))],
    },
    keys: [],
  };
  fp.keys = indexKeys(fp);
  return fp;
}

/** Inverted-index keys used to find candidate campaign members in O(1). */
export function indexKeys(fp: Fingerprint): string[] {
  const k = new Set<string>();
  if (fp.infra.espCampaign) k.add(`espc:${fp.infra.espCampaign}`);
  if (fp.infra.originNet) k.add(`net:${fp.infra.originNet}`);
  if (fp.content.skeleton) k.add(`skel:${fp.content.skeleton}`);
  if (fp.content.subjectTemplate && fp.content.subjectTemplate.length >= 8) k.add(`subj:${hash53(fp.content.subjectTemplate)}`);
  for (const h of fp.attachments.sha256) k.add(`att:${h}`);
  for (const s of fp.attachments.structural) k.add(`atts:${s}`);
  for (const d of fp.urls.domains.slice(0, 10)) k.add(`dom:${d}`);
  for (const t of fp.urls.templates.slice(0, 10)) k.add(`tpl:${hash53(t)}`);
  for (const p of fp.urls.paths.slice(0, 10)) k.add(`path:${hash53(p)}`);
  if (fp.sender.fromOrg) k.add(`from:${fp.sender.fromOrg}`);
  if (fp.infra.headerOrder && fp.infra.xMailer) k.add(`tool:${fp.infra.headerOrder}:${hash53(fp.infra.xMailer)}`);
  for (const band of lshBandKeys(fp.content.minhash)) k.add(band);
  return [...k];
}
