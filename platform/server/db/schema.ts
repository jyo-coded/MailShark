// case.db: investigations, evidence, analysis results, correlation output, reports, jobs, audit.
// Evidence bytes live in the content-addressed store; this database only references them by hash.
import type { Migration } from './sqlite';

export const CASE_MIGRATIONS: Migration[] = [
  {
    version: 1,
    name: 'initial',
    sql: `
CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);

CREATE TABLE users (
  id TEXT PRIMARY KEY,
  username TEXT NOT NULL UNIQUE COLLATE NOCASE,
  display_name TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('admin', 'investigator', 'viewer')),
  created_at INTEGER NOT NULL,
  disabled INTEGER NOT NULL DEFAULT 0,
  failed_logins INTEGER NOT NULL DEFAULT 0,
  locked_until INTEGER,
  last_login_at INTEGER
);

CREATE TABLE sessions (
  token_hash TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  csrf TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  last_seen_at INTEGER NOT NULL,
  ip TEXT,
  user_agent TEXT
);
CREATE INDEX sessions_user ON sessions(user_id);

CREATE TABLE cases (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  reference TEXT,
  description TEXT,
  status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'closed', 'archived')),
  created_by TEXT NOT NULL REFERENCES users(id),
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  legal_hold INTEGER NOT NULL DEFAULT 0,
  retention_until INTEGER,
  online_lookups INTEGER NOT NULL DEFAULT 0,
  correlation_version INTEGER NOT NULL DEFAULT 0,
  correlated_at INTEGER
);

CREATE TABLE case_members (
  case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role TEXT NOT NULL CHECK (role IN ('lead', 'investigator', 'viewer')),
  added_at INTEGER NOT NULL,
  PRIMARY KEY (case_id, user_id)
);

CREATE TABLE batches (
  id TEXT PRIMARY KEY,
  case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  created_by TEXT NOT NULL REFERENCES users(id),
  created_at INTEGER NOT NULL,
  file_count INTEGER NOT NULL,
  accepted_count INTEGER NOT NULL,
  total_bytes INTEGER NOT NULL,
  note TEXT
);
CREATE INDEX batches_case ON batches(case_id, created_at);

-- An uploaded file, exactly as received. Never modified.
CREATE TABLE evidence (
  id TEXT PRIMARY KEY,
  case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  batch_id TEXT NOT NULL REFERENCES batches(id) ON DELETE CASCADE,
  original_name TEXT NOT NULL,
  declared_type TEXT,
  format TEXT,
  size INTEGER NOT NULL,
  sha256 TEXT NOT NULL,
  sha1 TEXT NOT NULL,
  md5 TEXT NOT NULL,
  received_at INTEGER NOT NULL,
  uploaded_by TEXT NOT NULL REFERENCES users(id),
  status TEXT NOT NULL CHECK (status IN ('stored', 'duplicate', 'rejected', 'expanding', 'expanded', 'failed')),
  duplicate_of TEXT,
  message_count INTEGER NOT NULL DEFAULT 0,
  truncated INTEGER NOT NULL DEFAULT 0,
  error_code TEXT,
  error_detail TEXT
);
CREATE INDEX evidence_case ON evidence(case_id, received_at);
CREATE INDEX evidence_sha ON evidence(case_id, sha256);

-- One email message: the analysis unit. Original (.eml/.emlx), extracted (mbox) or reconstructed (.msg).
CREATE TABLE messages (
  id TEXT PRIMARY KEY,
  case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  evidence_id TEXT NOT NULL REFERENCES evidence(id) ON DELETE CASCADE,
  container_index INTEGER NOT NULL,
  byte_offset INTEGER,
  size INTEGER NOT NULL,
  sha256 TEXT NOT NULL,
  blob_store TEXT NOT NULL CHECK (blob_store IN ('evidence', 'derived')),
  derivation TEXT NOT NULL CHECK (derivation IN ('original', 'extracted-from-mbox', 'extracted-from-emlx', 'reconstructed-from-msg')),
  status TEXT NOT NULL CHECK (status IN ('queued', 'running', 'analyzed', 'failed', 'duplicate')),
  duplicate_of TEXT,
  attempts INTEGER NOT NULL DEFAULT 0,
  subject TEXT,
  from_addr TEXT,
  from_name TEXT,
  to_addr TEXT,
  sent_at INTEGER,
  message_id TEXT,
  class TEXT,
  severity TEXT,
  confidence TEXT,
  score INTEGER,
  coverage REAL,
  verdict TEXT,
  finding_count INTEGER NOT NULL DEFAULT 0,
  ioc_count INTEGER NOT NULL DEFAULT 0,
  intel_hits INTEGER NOT NULL DEFAULT 0,
  cluster_id TEXT,
  error_code TEXT,
  error_detail TEXT,
  created_at INTEGER NOT NULL,
  analyzed_at INTEGER,
  engine_version TEXT
);
CREATE INDEX messages_case ON messages(case_id, status);
CREATE INDEX messages_case_class ON messages(case_id, class);
CREATE INDEX messages_sha ON messages(case_id, sha256);
CREATE INDEX messages_evidence ON messages(evidence_id, container_index);
CREATE INDEX messages_cluster ON messages(cluster_id);

-- Full engine report (gzip JSON) + reproducibility metadata.
CREATE TABLE results (
  message_id TEXT PRIMARY KEY REFERENCES messages(id) ON DELETE CASCADE,
  report_gz BLOB NOT NULL,
  report_sha256 TEXT NOT NULL,
  fingerprint_json TEXT NOT NULL,
  engine_version TEXT NOT NULL,
  config_hash TEXT NOT NULL,
  intel_snapshot TEXT,
  options_json TEXT NOT NULL,
  duration_ms REAL,
  created_at INTEGER NOT NULL
);

CREATE TABLE findings (
  message_id TEXT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
  case_id TEXT NOT NULL,
  finding_id TEXT NOT NULL,
  category TEXT NOT NULL,
  severity TEXT NOT NULL,
  weight REAL NOT NULL,
  title TEXT NOT NULL,
  PRIMARY KEY (message_id, finding_id)
);
CREATE INDEX findings_case ON findings(case_id, finding_id);

-- Normalised indicator values shared by all cases (values only; who saw them is in observations).
CREATE TABLE indicators (
  id INTEGER PRIMARY KEY,
  type TEXT NOT NULL,
  value TEXT NOT NULL,
  UNIQUE (type, value)
);

-- Observed fact: message X contains indicator Y in role Z at component ref.
CREATE TABLE observations (
  message_id TEXT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
  indicator_id INTEGER NOT NULL REFERENCES indicators(id),
  case_id TEXT NOT NULL,
  role TEXT NOT NULL,
  ref TEXT NOT NULL,
  context TEXT,
  suspicious INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (message_id, indicator_id, role)
);
CREATE INDEX observations_indicator ON observations(indicator_id, case_id);
CREATE INDEX observations_case ON observations(case_id, role);

-- External intelligence matches (exact after normalisation), with the source record's provenance.
CREATE TABLE intel_matches (
  id INTEGER PRIMARY KEY,
  case_id TEXT NOT NULL,
  message_id TEXT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
  indicator_id INTEGER NOT NULL REFERENCES indicators(id),
  source TEXT NOT NULL,
  match_type TEXT NOT NULL,
  matched_value TEXT NOT NULL,
  record_json TEXT NOT NULL,
  event_id TEXT,
  strength REAL NOT NULL,
  matched_at INTEGER NOT NULL
);
CREATE INDEX intel_matches_case ON intel_matches(case_id, message_id);
CREATE INDEX intel_matches_event ON intel_matches(case_id, source, event_id);

-- Correlation output (rebuilt as a whole per case on each correlation run).
CREATE TABLE clusters (
  id TEXT PRIMARY KEY,
  case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  label TEXT NOT NULL,
  size INTEGER NOT NULL,
  confidence TEXT NOT NULL,
  cohesion REAL NOT NULL,
  first_seen INTEGER,
  last_seen INTEGER,
  verdict TEXT,
  profile_json TEXT NOT NULL,
  external_json TEXT NOT NULL,
  method TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX clusters_case ON clusters(case_id);

CREATE TABLE edges (
  case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  a TEXT NOT NULL,
  b TEXT NOT NULL,
  tier TEXT NOT NULL CHECK (tier IN ('exact', 'probable')),
  score REAL NOT NULL,
  evidence_json TEXT NOT NULL,
  PRIMARY KEY (case_id, a, b)
);

CREATE TABLE external_campaigns (
  case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  source TEXT NOT NULL,
  event_id TEXT NOT NULL,
  name TEXT NOT NULL,
  assessment TEXT NOT NULL,
  confidence TEXT NOT NULL,
  message_count INTEGER NOT NULL,
  detail_json TEXT NOT NULL,
  PRIMARY KEY (case_id, source, event_id)
);

CREATE TABLE reports (
  id TEXT PRIMARY KEY,
  case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  created_by TEXT NOT NULL REFERENCES users(id),
  created_at INTEGER NOT NULL,
  scope TEXT NOT NULL,
  scope_ref TEXT,
  format TEXT NOT NULL CHECK (format IN ('json', 'md', 'docx')),
  file_sha256 TEXT NOT NULL,
  data_sha256 TEXT NOT NULL,
  size INTEGER NOT NULL,
  report_uuid TEXT NOT NULL,
  schema_version TEXT NOT NULL
);
CREATE INDEX reports_case ON reports(case_id, created_at);

CREATE TABLE jobs (
  id INTEGER PRIMARY KEY,
  kind TEXT NOT NULL CHECK (kind IN ('expand', 'analyze', 'correlate')),
  case_id TEXT,
  ref TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('queued', 'running', 'done', 'failed', 'cancelled')),
  priority INTEGER NOT NULL DEFAULT 5,
  attempts INTEGER NOT NULL DEFAULT 0,
  max_attempts INTEGER NOT NULL DEFAULT 3,
  run_after INTEGER NOT NULL,
  leased_until INTEGER,
  last_error TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE INDEX jobs_ready ON jobs(status, priority, run_after);
CREATE INDEX jobs_ref ON jobs(kind, ref);

-- Processing history (per message / evidence item), separate from the audit log.
CREATE TABLE events (
  id INTEGER PRIMARY KEY,
  case_id TEXT NOT NULL,
  subject_type TEXT NOT NULL,
  subject_id TEXT NOT NULL,
  ts INTEGER NOT NULL,
  kind TEXT NOT NULL,
  detail TEXT
);
CREATE INDEX events_subject ON events(subject_type, subject_id, ts);
CREATE INDEX events_case ON events(case_id, ts);

-- Append-only, hash-chained audit log.
CREATE TABLE audit (
  seq INTEGER PRIMARY KEY,
  ts INTEGER NOT NULL,
  user_id TEXT,
  username TEXT,
  action TEXT NOT NULL,
  case_id TEXT,
  target TEXT,
  details TEXT,
  ip TEXT,
  prev_hash TEXT NOT NULL,
  hash TEXT NOT NULL
);
CREATE INDEX audit_case ON audit(case_id, seq);
CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
`,
  },
];
