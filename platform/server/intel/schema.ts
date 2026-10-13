// intel.db: external intelligence and enrichment data. Rebuildable from the sources at any time;
// kept separate from case.db so a feed refresh can never touch evidence or results.
import type { Migration } from '../db/sqlite';

export const INTEL_MIGRATIONS: Migration[] = [
  {
    version: 1,
    name: 'initial',
    sql: `
CREATE TABLE sources (
  id TEXT PRIMARY KEY,
  enabled INTEGER NOT NULL DEFAULT 1,
  last_attempt INTEGER,
  last_success INTEGER,
  last_error TEXT,
  etag TEXT,
  last_modified TEXT,
  record_count INTEGER NOT NULL DEFAULT 0,
  event_count INTEGER NOT NULL DEFAULT 0,
  snapshot_sha256 TEXT,
  next_due INTEGER,
  state_json TEXT
);

-- Indicator listings. One row per (source, type, value); refreshed per source.
CREATE TABLE indicators (
  source TEXT NOT NULL,
  type TEXT NOT NULL,
  value TEXT NOT NULL,
  first_seen INTEGER,
  last_seen INTEGER,
  threat TEXT,
  family TEXT,
  tags TEXT,
  confidence INTEGER,
  reference TEXT,
  external_id TEXT,
  extra TEXT,
  PRIMARY KEY (source, type, value)
) WITHOUT ROWID;
CREATE INDEX indicators_lookup ON indicators(type, value);

-- Campaign / event level records (MISP events, OTX pulses).
CREATE TABLE events (
  source TEXT NOT NULL,
  id TEXT NOT NULL,
  name TEXT NOT NULL,
  date INTEGER,
  updated_at INTEGER,
  org TEXT,
  tags TEXT,
  threat_level INTEGER,
  reference TEXT,
  attribute_count INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (source, id)
) WITHOUT ROWID;

CREATE TABLE event_indicators (
  source TEXT NOT NULL,
  event_id TEXT NOT NULL,
  type TEXT NOT NULL,
  value TEXT NOT NULL,
  category TEXT,
  to_ids INTEGER,
  comment TEXT,
  PRIMARY KEY (source, event_id, type, value)
) WITHOUT ROWID;
CREATE INDEX event_indicators_lookup ON event_indicators(type, value);

-- IPv4 network ranges (Spamhaus DROP).
CREATE TABLE cidr4 (
  source TEXT NOT NULL,
  start INTEGER NOT NULL,
  end INTEGER NOT NULL,
  cidr TEXT NOT NULL,
  label TEXT,
  reference TEXT
);
CREATE INDEX cidr4_start ON cidr4(start);

-- Enrichment: IP → ASN (iptoasn, public domain) and domain popularity (Tranco).
CREATE TABLE asn4 (start INTEGER NOT NULL, end INTEGER NOT NULL, asn INTEGER NOT NULL, name TEXT);
CREATE INDEX asn4_start ON asn4(start);
CREATE TABLE asn6 (start TEXT NOT NULL, end TEXT NOT NULL, asn INTEGER NOT NULL, name TEXT);
CREATE INDEX asn6_start ON asn6(start);
CREATE TABLE popular (domain TEXT PRIMARY KEY, rank INTEGER NOT NULL) WITHOUT ROWID;

-- Cached online lookups (OTX, VirusTotal, MISP instance...). Each one is also in the audit log.
CREATE TABLE lookups (
  source TEXT NOT NULL,
  type TEXT NOT NULL,
  value TEXT NOT NULL,
  fetched_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  status TEXT NOT NULL,
  result_json TEXT NOT NULL,
  PRIMARY KEY (source, type, value)
) WITHOUT ROWID;

CREATE TABLE sync_log (
  id INTEGER PRIMARY KEY,
  source TEXT NOT NULL,
  started_at INTEGER NOT NULL,
  finished_at INTEGER,
  status TEXT NOT NULL,
  records INTEGER,
  events INTEGER,
  bytes INTEGER,
  snapshot_sha256 TEXT,
  error TEXT
);
CREATE INDEX sync_log_source ON sync_log(source, started_at);
`,
  },
];
