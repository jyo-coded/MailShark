// API response shapes used by the client. Engine and server types are imported type-only, so the
// client always agrees with what the server actually returns.
import type { Report, Finding, Severity, LinkAnalysis, AttachmentAnalysis, Ioc } from '../../../engine/src/types';
import type { FindingDoc } from '../../../engine/src/catalog';
import type { GraphPayload, GNode, GEdge, NodeKind } from '../../server/graph/build';
import type { SourceInfo } from '../../server/intel/service';

export type { Report, Finding, Severity, LinkAnalysis, AttachmentAnalysis, Ioc, FindingDoc, GraphPayload, GNode, GEdge, NodeKind, SourceInfo };

export type Cls = 'malicious' | 'suspicious' | 'inconclusive' | 'benign' | 'failed';
export const CLASSES: Cls[] = ['malicious', 'suspicious', 'inconclusive', 'benign', 'failed'];
export type Role = 'admin' | 'investigator' | 'viewer';
export type CaseRole = 'lead' | 'investigator' | 'viewer';

export interface User {
  id: string;
  username: string;
  displayName: string;
  role: Role;
  disabled: boolean;
  createdAt: number;
  lastLoginAt: number | null;
}

export interface PlatformInfo {
  version: string;
  engine: string;
  limits: { filesPerBatch: number; fileBytes: number; batchBytes: number; messagesPerContainer: number };
  formats: string[];
  onlineLookupsAllowed: boolean;
  thresholds: { caution: number; danger: number; coverageFloor: number };
}

export interface SessionInfo {
  user: User | null;
  csrf: string | null;
  setupNeeded: boolean;
  expiresAt?: number;
  platform?: PlatformInfo;
}

export interface CaseSummary {
  id: string;
  name: string;
  reference: string | null;
  description: string | null;
  status: 'open' | 'closed' | 'archived';
  createdAt: number;
  updatedAt: number;
  createdBy: { id: string; username: string; displayName: string } | null;
  legalHold: boolean;
  retentionUntil: number | null;
  onlineLookups: boolean;
  correlatedAt: number | null;
  myRole: CaseRole;
  counts: {
    evidence: number;
    evidenceBytes: number;
    messages: number;
    analyzed: number;
    pending: number;
    failed: number;
    duplicates: number;
    malicious: number;
    suspicious: number;
    benign: number;
    inconclusive: number;
    withIntel: number;
    clusters: number;
    threatClusters: number;
    externalCampaigns: number;
  };
  lastAnalyzedAt: number | null;
}

export interface CaseStats {
  severity: Record<string, number>;
  timeline: { start: number; bucketMs: number; buckets: { t: number; malicious: number; suspicious: number; other: number }[] } | null;
  topFindings: { id: string; title: string; category: string; severity: string; messages: number }[];
  topIntel: { id: number; type: string; value: string; messages: number; sources: string[] }[];
  topSenders: { domain: string; messages: number; malicious: number; suspicious: number }[];
  clusters: { id: string; label: string; size: number; verdict: string; confidence: string; firstSeen: number | null; lastSeen: number | null }[];
  external: Record<string, number>;
  failures: { code: string | null; n: number }[];
}

export interface Progress {
  messages: { queued: number; running: number; analyzed: number; failed: number; duplicate: number; total: number };
  evidence: Record<string, number>;
  jobs: { kind: string; status: string; n: number }[];
  correlation: { correlatedAt: number | null; version: number; pending: boolean };
  done: boolean;
}

export interface BatchRow {
  id: string;
  createdAt: number;
  fileCount: number;
  acceptedCount: number;
  totalBytes: number;
  note: string | null;
  createdBy: string;
  messages: number;
  pending: number;
  failed: number;
}

export interface EvidenceRow {
  id: string;
  batchId: string;
  originalName: string;
  declaredType: string | null;
  format: string | null;
  size: number;
  sha256: string;
  sha1: string;
  md5: string;
  receivedAt: number;
  uploadedBy: string;
  status: string;
  duplicateOf: string | null;
  messageCount: number | null;
  truncated: number | null;
  errorCode: string | null;
  errorDetail: string | null;
  analyzed: number;
  pending: number;
  failed: number;
}

export interface EvidenceDetail {
  evidence: Record<string, unknown> & { id: string; original_name: string; sha256: string; sha1: string; md5: string; size: number; status: string; format: string | null; received_at: number };
  messages: { id: string; containerIndex: number; byteOffset: number | null; size: number; sha256: string; derivation: string; status: string; class: string | null; subject: string | null }[];
  history: { ts: number; kind: string; detail: string | null }[];
}

export interface BatchResult {
  batchId: string;
  accepted: number;
  rejected: number;
  duplicates: number;
  evidence: { id: string; originalName: string; size: number; sha256: string | null; format: string | null; status: string; duplicateOf: string | null; error: { code: string; message: string } | null }[];
}

export interface MessageSummary {
  id: string;
  evidenceId: string;
  evidenceName: string | null;
  containerIndex: number;
  derivation: string;
  status: string;
  duplicateOf: string | null;
  subject: string | null;
  from: string | null;
  fromName: string | null;
  to: string | null;
  sentAt: number | null;
  messageId: string | null;
  class: Cls | null;
  severity: string | null;
  confidence: string | null;
  score: number | null;
  coverage: number | null;
  findingCount: number;
  iocCount: number;
  intelHits: number;
  clusterId: string | null;
  clusterLabel: string | null;
  error: { code: string; detail: string | null } | null;
  receivedAt: number;
  analyzedAt: number | null;
  size: number;
  sha256: string;
}

export interface MessageList {
  total: number;
  page: number;
  pageSize: number;
  items: MessageSummary[];
  facets: { class: string | null; status: string; n: number }[];
}

export interface IntelMatch {
  source: string;
  matchType: string;
  matchedValue: string;
  indicatorType: string;
  indicator: string;
  strength: number;
  matchedAt: number;
  eventId: string | null;
  record: { firstSeen?: number | null; lastSeen?: number | null; threat?: string | null; family?: string | null; tags?: string | null; confidence?: number | null; reference?: string | null; externalId?: string | null; suppressed?: string | null } | null;
}

export interface SharedIndicator {
  family: string;
  type: string;
  value: string;
  strength: number;
  discounts: string[];
}

export interface RelatedMessage {
  message: Partial<MessageSummary> & { id: string };
  tier: 'exact' | 'probable';
  score: number;
  shared: SharedIndicator[];
  layers: Record<string, number | null>;
  hardLink: string | null;
  indicatorScore: number;
  similarity: number;
}

export interface ExternalAssociation {
  source: string;
  eventId: string;
  name: string;
  assessment: 'reported-association' | 'possible-association';
  confidence: string;
  reference: string | null;
  date: number | null;
  org: string | null;
  tags: string[];
  rationale: string[];
  indicators: { type: string; value: string; matchType: string; strength: number; roles?: string[]; messages?: number }[];
  messageCount?: number;
  messages?: string[];
}

export interface MessageDetail {
  message: MessageSummary;
  analyzedAs: string | null;
  provenance: {
    evidenceId: string;
    evidenceName: string;
    evidenceSha256: string;
    format: string | null;
    batchId: string;
    receivedAt: number;
    uploadedBy: string | null;
    derivation: string;
    containerIndex: number;
    byteOffset: number | null;
    messageSha256: string;
    messageSize: number;
    storedAs: string;
  } | null;
  report: Report | null;
  processing: { engineVersion: string; configHash: string; intelSnapshot: string | null; durationMs: number | null; reportSha256: string; analyzedAt: number; options: unknown; attempts: number } | null;
  findingDocs: Record<string, FindingDoc>;
  intel: IntelMatch[];
  cluster: { id: string; label: string; confidence: string; size: number; verdict: string; cohesion: number } | null;
  related: RelatedMessage[];
  externalCampaigns: ExternalAssociation[];
  history: { ts: number; kind: string; detail: unknown }[];
  duplicates: { id: string; evidence_id: string }[];
}

export interface RawView {
  size: number;
  truncated: boolean;
  encoding: string;
  text: string;
  headerEnd: number;
  headers: { name: string; start: number; end: number }[];
  sha256: string;
  derivation: string;
}

export interface IndicatorRow {
  id: number;
  type: string;
  value: string;
  messages: number;
  roles: string[];
  suspicious: boolean;
  intelHits: number;
  intelSources: string[];
  firstSeen: number | null;
  lastSeen: number | null;
}

export interface IndicatorList {
  total: number;
  page: number;
  pageSize: number;
  types: { type: string; n: number }[];
  items: IndicatorRow[];
}

export interface IntelListing {
  source: string;
  type: string;
  value: string;
  matchType: string;
  firstSeen: number | null;
  lastSeen: number | null;
  threat: string | null;
  family: string | null;
  tags: string | null;
  confidence: number | null;
  reference: string | null;
  externalId: string | null;
  suppressed: string | null;
}

export interface IndicatorDetail {
  indicator: { id: number; type: string; value: string; registrable: string | null; popularityRank: number | null; asn: { asn: number; name: string | null } | null };
  observations: { message: MessageSummary; role: string; ref: string; context: string | null; suspicious: boolean }[];
  caseMatches: { source: string; matchType: string; matchedValue: string; strength: number; matchedAt: number; messageId: string; record: IntelMatch['record'] }[];
  currentListings: IntelListing[];
  events: { source: string; eventId: string; name: string; date: number | null; reference: string | null; org: string | null; tags: string[]; threatLevel: number | null; type: string; value: string; category: string | null; matchType?: string; suppressed?: string | null }[];
  onlineLookups: { source: string; fetchedAt: number; status: string; result: unknown }[];
  otherCases: { caseId: string; caseName: string; messages: number }[];
}

export interface LookupOutcome {
  source: string;
  status: 'found' | 'not-found' | 'error' | 'skipped';
  detail: string;
  cached: boolean;
  fetchedAt: number;
  hits: IntelListing[];
  events: { eventId: string; name: string; date: number | null; reference: string | null }[];
}

export interface AttributeSpread {
  attr: string;
  label: string;
  values: string[];
  coverage: number;
}

export interface ClusterRow {
  id: string;
  label: string;
  size: number;
  confidence: string;
  cohesion: number;
  density: number;
  exactEdges: number;
  firstSeen: number | null;
  lastSeen: number | null;
  verdict: 'threat' | 'bulk' | 'mixed';
  invariants: string[];
  rotated: string[];
  sharedIndicators: (SharedIndicator & { messages: number })[];
  external: { source: string; eventId: string; name: string; assessment: string; confidence: string }[];
}

export interface ClusterDetail extends Omit<ClusterRow, 'invariants' | 'rotated'> {
  method: string;
  profile: { size: number; invariants: AttributeSpread[]; rotated: AttributeSpread[]; attackerCost: number; firstSeen: number; lastSeen: number; senders: string[]; domains: string[]; attachments: number };
  messages: (MessageSummary & { membership: number })[];
  relationships: { a: string; b: string; tier: 'exact' | 'probable'; score: number; evidence: { shared: SharedIndicator[]; layers: Record<string, number | null>; hardLink: string | null; indicatorScore: number; similarity: number } }[];
}

export interface ReportRow {
  id: string;
  createdAt: number;
  createdBy: string;
  scope: string;
  scopeRef: string | null;
  format: 'json' | 'md' | 'docx';
  fileSha256: string;
  dataSha256: string;
  size: number;
  reportId: string;
  schemaVersion: string;
}

export interface AuditEntry {
  seq: number;
  ts: number;
  user_id?: string | null;
  username: string | null;
  action: string;
  case_id?: string | null;
  target: string | null;
  details: string | null;
  ip?: string | null;
  prev_hash?: string;
  hash?: string;
}

export interface Member {
  user_id: string;
  username: string;
  display_name: string;
  role: CaseRole;
  added_at: number;
}

export interface Health {
  status: string;
  version: string;
  engine: string;
  uptimeSec: number;
  database: string;
  workers: { size: number; busy: number; queued: number };
  queue: { queued: number; running: number; failed24h: number };
  intel: { current: number; stale: number; unavailable: number; total: number };
}
