// MailShark engine: shared types. The report schema is versioned; bump REPORT_SCHEMA on breaking changes.

export const REPORT_SCHEMA = 'mailshark.report/1' as const;

export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';
export type Verdict = 'safe' | 'caution' | 'danger';
export type Confidence = 'low' | 'medium' | 'high';
export type Category =
  | 'sender'
  | 'auth'
  | 'route'
  | 'links'
  | 'content'
  | 'html'
  | 'attachments'
  | 'structure'
  | 'intel'
  | 'campaign';

export interface Evidence {
  label: string;
  value: string;
  mono?: boolean;
}

export interface Finding {
  id: string;
  category: Category;
  severity: Severity;
  title: string;
  detail: string;
  /** Contribution to the risk logit. Negative values are trust signals. */
  weight: number;
  evidence?: Evidence[];
}

export interface AddressInfo {
  name: string;
  address: string;
  domain: string;
  orgDomain: string;
}

export interface HeaderEntry {
  name: string;
  value: string;
}

// ── Route ────────────────────────────────────────────────────────────────────

export interface Hop {
  index: number; // 0 = newest (top-most header)
  raw: string;
  fromHost: string | null;
  fromRdns: string | null;
  fromIp: string | null;
  fromIpPublic: boolean;
  byHost: string | null;
  protocol: string | null;
  tls: string | null;
  timestamp: number | null; // epoch ms
  delaySec: number | null; // vs. previous (older) hop
  trusted: boolean; // written by the recipient's own infrastructure
}

export interface RouteAnalysis {
  hops: Hop[]; // oldest → newest
  receiverOrg: string | null;
  originIp: string | null;
  originHost: string | null;
  originOrg: string | null;
  totalTransitSec: number | null;
  dateHeader: number | null;
  dateSkewSec: number | null;
}

// ── Authentication ──────────────────────────────────────────────────────────

export type AuthResult = 'pass' | 'fail' | 'softfail' | 'neutral' | 'none' | 'temperror' | 'permerror' | 'policy' | 'bestguesspass' | 'unknown';

export interface AuthMethodResult {
  method: string; // spf | dkim | dmarc | arc | compauth | ...
  result: AuthResult;
  props: Record<string, string>;
  comment: string | null;
}

export interface DkimSignature {
  domain: string;
  selector: string;
  algorithm: string;
  signedHeaders: string[];
}

export interface AuthAnalysis {
  source: 'trusted' | 'topmost' | 'none';
  authServId: string | null;
  spf: AuthResult;
  dkim: AuthResult;
  dmarc: AuthResult;
  arc: AuthResult;
  compauth: AuthResult | null;
  dmarcPolicy: string | null;
  spfDomain: string | null;
  dkimDomains: string[]; // d= of passing signatures
  headerFrom: string | null;
  spfAligned: boolean | null;
  dkimAligned: boolean | null;
  signatures: DkimSignature[];
  results: AuthMethodResult[];
}

// ── Sender ──────────────────────────────────────────────────────────────────

export interface SenderAnalysis {
  from: AddressInfo | null;
  replyTo: AddressInfo[];
  returnPath: AddressInfo | null;
  sender: AddressInfo | null;
  isFreemail: boolean;
  claimedBrands: string[];
  impersonatedBrand: string | null;
  verifiedBrand: string | null;
  lookalikeOf: string | null;
  lookalikeKind: 'homoglyph' | 'typosquat' | 'embedded' | 'subdomain' | null;
  displayNameAddress: string | null;
  firstTimeSender: boolean | null;
  /** The recipient's own organisation is used as a lure (display name/subject) by an outside sender. */
  impersonatesRecipientOrg: string | null;
  /** Display name poses as an IT / mail-system role. */
  roleName: string | null;
}

// ── Links ───────────────────────────────────────────────────────────────────

export type LinkSource = 'html-anchor' | 'html-form' | 'html-other' | 'text' | 'attachment' | 'qr' | 'header';

export interface LinkAnalysis {
  url: string;
  unwrappedFrom: string | null;
  sources: LinkSource[];
  displayText: string | null;
  scheme: string;
  host: string;
  unicodeHost: string | null;
  regDomain: string | null;
  tld: string | null;
  isIp: boolean;
  template: string;
  flags: string[];
  risk: 0 | 1 | 2 | 3; // 0 clean, 1 note, 2 suspicious, 3 dangerous
  lookalikeOf: string | null;
  intelHit: string | null;
}

// ── HTML ────────────────────────────────────────────────────────────────────

export interface HtmlAnalysis {
  present: boolean;
  tagCount: number;
  skeletonHash: string | null;
  classHash: string | null;
  forms: { action: string | null; inputs: string[]; hasPassword: boolean }[];
  scripts: number;
  iframes: number;
  embeds: number;
  metaRefresh: string | null;
  baseHref: string | null;
  images: number;
  remoteImageHosts: string[];
  trackingPixels: number;
  hiddenTextChars: number;
  zeroWidthChars: number;
  visibleTextChars: number;
  imageOnly: boolean;
}

// ── Content ─────────────────────────────────────────────────────────────────

export interface ContentAnalysis {
  subject: string;
  subjectTemplate: string;
  language: string;
  intent: string | null; // primary intent id
  intents: { id: string; label: string; score: number; matches: string[] }[];
  urgency: 0 | 1 | 2 | 3;
  requestedActions: string[];
  brandMentions: string[];
  genericGreeting: boolean;
  phoneNumbers: string[];
  fakeReply: boolean;
  subjectHomoglyph: boolean;
  personalized: string | null;
  phoneInHeader: boolean;
  splitWords: boolean;
  attachmentInstructions: string[];
  textPreview: string;
}

// ── Attachments ─────────────────────────────────────────────────────────────

export interface ArchiveEntry {
  name: string;
  size: number;
  encrypted: boolean;
}

export interface AttachmentAnalysis {
  filename: string;
  declaredType: string;
  detectedType: string;
  extension: string;
  size: number;
  inline: boolean;
  sha256: string;
  sha1: string;
  md5: string;
  entropy: number;
  structural: string;
  flags: string[];
  risk: 0 | 1 | 2 | 3;
  entries: ArchiveEntry[];
  urls: string[];
  qr: string | null;
}

// ── Structure ───────────────────────────────────────────────────────────────

export interface MimePart {
  contentType: string;
  depth: number;
  encoding: string | null;
  charset: string | null;
  filename: string | null;
  size: number;
}

export interface StructureAnalysis {
  parts: MimePart[];
  partCount: number;
  maxDepth: number;
  hasText: boolean;
  hasHtml: boolean;
  textHtmlDivergence: number | null; // 0 same … 1 completely different
  duplicateHeaders: string[];
  anomalies: string[];
}

// ── ESP (bulk sender) ───────────────────────────────────────────────────────

export interface EspInfo {
  id: string;
  name: string;
  campaignId: string | null;
  customerId: string | null;
  evidence: string;
}

// ── Fingerprint (campaign correlation) ──────────────────────────────────────

export interface Fingerprint {
  version: 1;
  time: number;
  sender: {
    fromDomain: string | null;
    fromOrg: string | null;
    localTemplate: string | null;
    displayName: string | null;
    replyToOrg: string | null;
    returnPathOrg: string | null;
  };
  infra: {
    originIp: string | null;
    originNet: string | null;
    originOrg: string | null;
    xMailer: string | null;
    dkimDomains: string[];
    dkimSelectors: string[];
    dkimHeaderSet: string | null;
    headerOrder: string | null;
    messageIdTemplate: string | null;
    messageIdDomain: string | null;
    esp: string | null;
    espCampaign: string | null;
  };
  content: {
    subjectTemplate: string;
    subjectTokens: string[];
    minhash: number[];
    simhash: string;
    skeleton: string | null;
    classHash: string | null;
    intent: string | null;
    brand: string | null;
    actions: string[];
  };
  urls: {
    domains: string[];
    templates: string[];
    /** Path-only templates: survive domain rotation (phishing-kit layout). */
    paths: string[];
  };
  attachments: {
    sha256: string[];
    structural: string[];
    nameTemplates: string[];
  };
  keys: string[];
}

// ── Report ──────────────────────────────────────────────────────────────────

export interface Report {
  schema: typeof REPORT_SCHEMA;
  engineVersion: string;
  id: string; // SHA-256 of the raw message bytes
  analyzedAt: string;
  sizeBytes: number;
  hashes: { sha256: string; sha1: string; md5: string };
  summary: {
    subject: string;
    from: AddressInfo | null;
    to: AddressInfo[];
    date: string | null;
    messageId: string | null;
  };
  verdict: Verdict;
  score: number;
  confidence: Confidence;
  headline: string;
  oneLiner: string;
  findings: Finding[];
  sender: SenderAnalysis;
  auth: AuthAnalysis;
  route: RouteAnalysis;
  links: LinkAnalysis[];
  html: HtmlAnalysis;
  content: ContentAnalysis;
  attachments: AttachmentAnalysis[];
  structure: StructureAnalysis;
  esp: EspInfo | null;
  headers: HeaderEntry[];
  fingerprint: Fingerprint;
  timings: Record<string, number>;
}

// ── Environment hooks ───────────────────────────────────────────────────────

export interface IntelProvider {
  /** Returns the list name that contains this host/domain, or null. */
  lookupDomain(domain: string): string | null;
  /** Returns the list name that contains this exact URL, or null. */
  lookupUrl?(url: string): string | null;
}

export type QrDecoder = (bytes: Uint8Array, mimeType: string) => Promise<string | null>;

export interface AnalyzeContext {
  /** How many earlier emails from this sender address the user has received (local history). */
  senderSeenCount?: number | null;
}

export interface AnalyzeOptions {
  now?: Date;
  context?: AnalyzeContext;
  intel?: IntelProvider | null;
  qrDecoder?: QrDecoder | null;
  /** Attachments larger than this are hashed but not deep-inspected. */
  maxInspectBytes?: number;
}
