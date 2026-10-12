# MailShark Forensic Platform: design

The platform is a self-hosted web application for forensic investigators who receive email *evidence files* rather than mailbox access. It is a second application built on the same analysis engine as the browser extension. The extension keeps working on its own; nothing in it depends on the platform.

This document records the design decisions and the reasons for them. Validation results are in [VALIDATION.md](VALIDATION.md). Operating instructions are in [README.md](README.md).

## 1. Constraints taken from the existing code

| Fact | Consequence |
|---|---|
| The detection engine (`engine/src`, TypeScript) is pure: no DOM, no network, WebCrypto only. It already runs in Node for the accuracy harness. | The backend is Node.js and imports the engine directly. There is one engine and no port to another language. |
| The extension bundles the same engine. | Engine changes must be backwards-compatible: new report fields are optional and additive. The extension's tests, linter run and real-Firefox e2e stay green. |
| The Python `lab/` is the course deliverable (pandas clustering, rotation experiment). | It stays as is. The platform re-implements campaign correlation in TypeScript on top of engine fingerprints, so analysis and correlation share one data model. |
| UI conventions: Preact, esbuild, Geist fonts, Lucide icons, d3-force. | The dashboard UI reuses them. The design system is new: dense and instrument-like, unlike the extension's consumer look. |
| No server exists today. | Technologies are chosen for what a forensic workstation or small lab server needs, nothing more (§3). |

## 2. Responsibilities

```
                 ┌──────────────── platform/web (Preact SPA) ────────────────┐
                 │ cases · upload · message list/detail · campaigns · graph   │
                 │ reports · intelligence status · activity                   │
                 └──────────────────────────┬────────────────────────────────┘
                                            │ JSON over HTTPS (session cookie + CSRF header)
┌───────────────────────────────── platform/server (Fastify) ─────────────────────────────────┐
│ api/         routes, input validation, authorization, audit                                  │
│ evidence/    upload handling → format detection → write-once content-addressed store         │
│ jobs/        SQLite job queue (leases, retries) → worker_threads pool (timeouts, memory caps)│
│ analysis/    worker: container expansion (eml/mbox/msg/emlx) → ENGINE → platform model        │
│ intel/       source connectors → normalisation → intel.db; enrichment (ASN, popularity)       │
│ correlation/ indicator graph, specificity weighting, clustering, external campaign matching   │
│ graph/       entity/relationship graph queries with filters and incremental expansion         │
│ reports/     one report model → JSON (default, schema-versioned) · Markdown · DOCX            │
└──────────────────────────────────────────────────────────────────────────────────────────────┘
         │ case.db (cases, evidence, results, audit)     │ intel.db (feeds, enrichment; rebuildable)
         │ evidence/ (sha256-addressed, read-only files) │
```

- **Shared model** (`platform/shared/model.ts`): a deliberately non-email-specific vocabulary:
  - `Investigation`, `EvidenceItem`, `Artifact`
  - `Indicator`, `Observation`, `Finding`
  - `Relationship`, `Report`
- **Email specifics** live in the email analyzer. A future mobile or disk analyzer plugs in as another analyzer producing the same objects. The UI only branches on artifact kind for detail views.

## 3. Technology choices

| Need | Choice | Why not something else |
|---|---|---|
| HTTP API | Fastify 5 | Mature schema validation, body limits and multipart limits. Avoids hand-rolling parsers for untrusted input. |
| Persistence | SQLite via built-in `node:sqlite` (WAL) | No server, no native build step, transactional, a single file per database that can be preserved and hashed. One writer (the main thread), so no lock contention. |
| CPU-bound analysis | `worker_threads` pool | Keeps the API responsive during 100-file batches. A per-job timeout terminates a runaway parse, and per-worker heap limits contain memory blow-ups. |
| Outlook `.msg` | `@kenjiuno/msgreader` | OLE/MAPI parsing is out of scope to write ourselves. Output is clearly marked as a *reconstruction*. |
| DOCX | `docx` | Pure JS and MIT-licensed. Generates the document from the same report object as JSON and Markdown. |
| Graph rendering | Canvas 2D + `d3-force` + quadtree hit-testing | SVG degrades past a few thousand elements. Canvas gives full control over a restrained visual language. |

Rejected:
- **PostgreSQL / Redis / a message broker:** operational weight without a requirement that needs it at lab scale.
- **A Python backend:** it would duplicate the engine.
- **Server-side HTML rendering of email bodies:** never done (§8).

## 4. Analysis pipeline

1. **Upload.** `POST /api/cases/:id/batches` (multipart) has hard limits:
   - ≤ 100 files per batch
   - per-file and total size caps
   - field and part counts

   Each file streams to a temp file while SHA-256, SHA-1 and MD5 are computed. It is then moved into the store under its SHA-256 and marked read-only. The client-supplied name is recorded as metadata only and never used as a path.
2. **Format detection** is by content, not extension:
   - RFC 5322 message: `.eml`, `.txt`
   - Apple `.emlx`: byte-count prefix and plist trailer
   - mbox: `From ` separators, RFC 4155
   - Outlook `.msg`: OLE compound file
   - Anything else is rejected with a structured error.
3. **Expansion.** A container (mbox) yields one *message artifact* per message, each with its own hash and byte offset. `.msg` yields one reconstructed RFC 5322 artifact; its transport headers are taken from the file when present.
4. **Deduplication.**
   - The same file uploaded twice within a case links to the existing evidence item (recorded, not silently dropped).
   - The same message bytes reached through different containers share one analysis result.
5. **Jobs.** One job per message artifact, persisted in SQLite:
   - States: `queued → running → done | failed`.
   - A lease plus retry count lets work interrupted by a crash or restart resume.
   - Deterministic failures (unparseable input) are not retried; transient ones (worker crash, timeout) are retried up to a limit.
6. **Worker.**
   - Runs `analyzeEmail()` from the shared engine, with offline DKIM body-hash verification.
   - Builds the indicator list and evidence coverage.
   - Returns structured data only. Attachments are inspected as bytes in memory: never written out separately, never executed.
7. **Persistence and correlation.** The main thread stores results in one transaction, then schedules case correlation (debounced). Correlation feeds campaigns and the graph.

## 5. Classification model

Each analysed message gets exactly one class:

| Class | Rule |
|---|---|
| `malicious` | Risk ≥ the danger threshold **and** at least one high or critical finding backed by direct evidence in the message; *or* an exact match of a message indicator (URL, domain, attachment hash) on a high-confidence threat feed |
| `suspicious` | Risk ≥ the caution threshold, not malicious |
| `benign` | Risk < the caution threshold **and** evidence coverage ≥ the coverage floor |
| `inconclusive` | Risk < the caution threshold **but** coverage below the floor: the evidence needed to judge it was not present or not inspectable (no body text, encrypted parts, uninspectable archives, missing headers) |
| `failed` | Analysis could not complete; the error is recorded |

Definitions:
- **Risk score (0–100).** A logistic transform of the summed evidence weights, with category caps and trust credits. It is an *ordinal* measure and not a probability.
- **Evidence coverage (0–1).** The weighted share of evidence layers that were actually available and inspected:
  - header block, Received chain, authentication results from the receiving server
  - body text, HTML, links, attachments
- **Confidence (low / medium / high).** A rule over three quantities:
  - the margin between the risk score and the nearest decision threshold
  - coverage
  - the number of *independent* finding categories that agree

  Its meaning is empirical: VALIDATION.md reports the precision of each class at each confidence level on held-out data.

Missing evidence is never read as negative evidence. A message without `Authentication-Results` is reported as *authentication: not available in this evidence*, never as *failed*.

## 6. Findings

Every finding carries:
- `id`, category, severity and weight (its log-odds contribution)
- what was observed: evidence values plus *component references* such as `header:Received[2]`, `link[3]`, `attachment[1]`
- **method**:
  - `protocol`: RFC-defined check, e.g. DKIM body hash or alignment
  - `heuristic`: expert rule
  - `statistical`
  - `intel`: external list match
  - `correlation`
- why it matters
- known limitations
- recommended investigative actions
- MITRE ATT&CK technique where one applies

The catalogue is in `engine/src/catalog.ts`. It is shared with the extension, which ignores the extra fields.

Observed facts (header values, hashes, URLs), analytical inferences (findings, classification) and external intelligence (feed matches, campaign associations with source and timestamps) are stored and reported separately.

## 7. Campaign intelligence

The design is in [CAMPAIGNS.md](CAMPAIGNS.md). In short:
1. **Indicators** are normalised: URL canonical form, host, registrable domain, kit path template, addresses, IP, /24, ASN, attachment hashes and structure, phone numbers, wallets, ESP campaign ids, content sketches.
2. **Specificity weighting.** A shared indicator only counts as evidence if it is specific. Values are discounted when they are:
   - popular (Tranco) or shared platforms (PSL private section, free hosting, URL shorteners, ESP click-trackers)
   - large mail providers' sending networks
   - values seen with many unrelated senders (inverse document frequency over the investigation and history)
3. **Relationship tiers:**
   - **exact indicator match:** the same specific artifact
   - **probable relationship:** layered similarity of content, infrastructure, sender and timing
   - **externally reported association:** the indicator is listed in a named external event or campaign record
4. **Clusters.** Messages are connected by evidence-weighted edges and clustered with Louvain community detection. A component held together by one weak edge is therefore not merged. Every cluster records the edges, and the artifacts behind each edge, that justify it.
5. **External matching.** Message indicators are matched against the intelligence store (feeds and MISP events), plus opt-in online lookups that are recorded in the audit log because they disclose indicators. A suspicious message is never forced into a known campaign. It may stay unmatched, or form a new local cluster.

Thresholds are configuration with documented meaning. Their effect is measured in VALIDATION.md on labelled synthetic campaigns and on real-data silver labels.

## 8. Security model

- **Untrusted content.**
  - Email content and every value derived from it (names, HTML, URLs, attachment names, intelligence responses) is data.
  - It is rendered as text only; the UI never injects HTML.
  - HTML bodies are shown as source or as extracted text, never rendered.
  - The server never fetches URLs found in evidence.
- **SSRF.** Outbound requests go only to configured intelligence endpoints, which are fixed per connector. Lookups send indicator values only as query or path parameters to those hosts, and only when the investigator enables online lookups for the case.
- **Uploads.**
  - Streamed with size caps.
  - Stored by hash, never by name, so path traversal is impossible.
  - Format checked by content.
  - Archives inside emails are inspected in memory with entry-count and size caps; nothing is extracted to disk.
- **Authentication.** Local accounts:
  - scrypt password hashes
  - server-side sessions in HttpOnly, SameSite=Strict cookies
  - a CSRF token header on every state-changing request
  - login rate limiting and lockout

  The first administrator is created with a one-time setup token printed at start-up.
- **Authorisation.**
  - Roles: `admin`, `investigator`, `viewer`.
  - Case membership is checked on every case-scoped route.
  - Cross-case correlation only uses cases the requesting user can access.
- **Audit.** An append-only, hash-chained log records logins, uploads, analyses, evidence and report downloads, deletions, settings changes and every online intelligence lookup. `GET /api/admin/audit/verify` recomputes the chain.
- **HTTP hardening:**
  - strict CSP (`default-src 'self'`, no inline script)
  - `frame-ancestors 'none'`, `nosniff`, `no-referrer`
  - JSON-only API with explicit content types
- **Data handling.**
  - Evidence files are read-only and verified against their hash when served.
  - Deleting a case removes its evidence files and results and keeps an audit record holding the hashes only.
  - Retention dates and legal hold are per case.

## 9. Forensic integrity: what is and is not claimed

What the platform does:
- hashes every evidence file at intake
- preserves the original bytes unmodified
- records the derivation of every message artifact (container hash plus offset)
- records the engine version, the configuration hash and the intelligence snapshot used for each analysis
- keeps a tamper-evident audit log

Reports are generated from stored results, and each report records its own hash.

What it does **not** claim:
- conformity with ISO/IEC 27037, NIST SP 800-86 or any accreditation (not evaluated)
- legal admissibility (a matter for the jurisdiction and the examiner)

Limitations that affect reliability are listed in [LIMITATIONS.md](LIMITATIONS.md).
