# MailShark Forensic Platform

A self-hosted web platform for investigating email evidence: batch intake of `.eml`, `.emlx`, `.mbox`
and Outlook `.msg` files, per-message forensic analysis with documented findings, campaign
correlation inside a case, intelligence matching against locally synchronised feeds, an interactive
investigation graph, and reports in JSON, Markdown and DOCX.

It runs next to the MailShark browser extension and reuses the same analysis engine
(`engine/src`). The extension does not depend on the platform.

| Document | Contents |
| --- | --- |
| [DESIGN.md](DESIGN.md) | Architecture, pipeline, classification model, security model, integrity claims |
| [CAMPAIGNS.md](CAMPAIGNS.md) | Campaign correlation, external associations, intelligence sources (evaluated one by one) |
| [VALIDATION.md](VALIDATION.md) | What was tested, how, and the measured results |
| [LIMITATIONS.md](LIMITATIONS.md) | Known limitations and what the platform does not claim |

## Requirements

- Node.js **22.13 or later** (uses the built-in `node:sqlite`). Tested with Node 22.19 on Windows 11.
- About 600 MB of disk for the intelligence store when all public feeds are synchronised, plus the
  evidence you upload.
- Outbound HTTPS to the feed hosts listed in [CAMPAIGNS.md](CAMPAIGNS.md#sources) if you want
  intelligence. The platform works without it: indicators then simply are not matched.

## Run

```bash
npm ci
```

```bash
npm run platform
```

`npm run platform` builds `dist/platform` and starts the server on `http://127.0.0.1:7380`.
To start an existing build without rebuilding:

```bash
npm run platform:start
```

On the first start (no users yet) the console prints a one-time **setup token** and writes it to
`<data dir>/SETUP_TOKEN`. Open the address, enter the token and create the administrator. The token
is discarded once the administrator exists.

Download the intelligence feeds once (they also refresh on a schedule while the server runs):

```bash
npm run platform:intel-sync
```

Other commands of the server binary (`node dist/platform/server.mjs <command>`):

| Command | Purpose |
| --- | --- |
| `serve` | Start the web application (default). |
| `intel-sync [source …]` | Download intelligence feeds now (all enabled, or the named ones). |
| `create-user <username> <admin\|investigator\|viewer>` | Create a user; the password is read from stdin. |
| `reset-password <username>` | Set a new password from stdin and sign the user out everywhere. |
| `verify-evidence` | Re-hash every stored blob and report mismatches. |
| `audit-verify` | Verify the audit log hash chain. |

### Exposing it beyond localhost

The server binds to `127.0.0.1` by default. To serve a team, either terminate TLS in the server
(`MAILSHARK_TLS_CERT` / `MAILSHARK_TLS_KEY`, which also makes the session cookie `Secure`) or put it
behind a reverse proxy that terminates TLS, set `MAILSHARK_HOST=0.0.0.0`, `MAILSHARK_TRUST_PROXY=1`
and `MAILSHARK_COOKIE_SECURE=true`. Do not expose it over plain HTTP.

## Configuration

Everything is configured with environment variables; invalid values stop the server at start-up
with a message naming the variable.

### Server and storage

| Variable | Default | Meaning |
| --- | --- | --- |
| `MAILSHARK_DATA_DIR` | `./data` | Databases, evidence blobs, derived artifacts, reports. Back this directory up. |
| `MAILSHARK_HOST` | `127.0.0.1` | Listen address. |
| `MAILSHARK_PORT` | `7380` | Listen port. |
| `MAILSHARK_TLS_CERT`, `MAILSHARK_TLS_KEY` | unset | PEM certificate and key; both or neither. Enables HTTPS and HSTS. |
| `MAILSHARK_COOKIE_SECURE` | `true` with TLS, else `false` | Mark the session cookie `Secure` (set `true` behind a TLS proxy). |
| `MAILSHARK_TRUST_PROXY` | unset | `1` to trust `X-Forwarded-*` from a reverse proxy (client IPs in the audit log). |
| `MAILSHARK_LOG_LEVEL` | `info` | `fatal`, `error`, `warn`, `info` or `debug`. |
| `MAILSHARK_SESSION_IDLE_MIN` | `480` | Idle session timeout (minutes). |
| `MAILSHARK_SESSION_MAX_H` | `24` | Absolute session lifetime (hours). |

### Intake limits and processing

| Variable | Default | Meaning |
| --- | --- | --- |
| `MAILSHARK_MAX_FILES` | `100` | Files per batch (1–100; can be lowered, never raised above 100). |
| `MAILSHARK_MAX_FILE_MB` | `50` | Per-file limit. Larger files are recorded as rejected; their bytes are not kept. |
| `MAILSHARK_MAX_BATCH_MB` | `1024` | Per-batch limit; a larger batch is refused as a whole. |
| `MAILSHARK_MAX_MBOX_MESSAGES` | `10000` | Messages extracted from one mailbox file; the rest is recorded as truncated. |
| `MAILSHARK_WORKERS` | CPU count − 1 (max 8) | Analysis worker threads. |
| `MAILSHARK_WORKER_HEAP_MB` | `1024` | Heap limit per worker; a message exceeding it fails alone. |
| `MAILSHARK_ANALYSIS_TIMEOUT_S` | `120` | Per-message analysis timeout (the worker is replaced on timeout). |
| `MAILSHARK_EXPAND_TIMEOUT_S` | `600` | Per-file container expansion timeout. |
| `MAILSHARK_CORRELATE_TIMEOUT_S` | `900` | Per-case correlation timeout. |

### Analysis thresholds

| Variable | Default | Meaning |
| --- | --- | --- |
| `MAILSHARK_CAUTION_AT` | `35` | Risk score from which a message is *suspicious*. |
| `MAILSHARK_DANGER_AT` | `70` | Risk score from which a message can be *malicious* (with a strong finding or an intelligence match). |
| `MAILSHARK_COVERAGE_FLOOR` | `0.5` | Below this evidence coverage a low-risk message is *inconclusive*, not benign. |
| `MAILSHARK_CORR_EDGE` | `0.6` | Combined evidence needed for a *probable* relationship between two messages. |
| `MAILSHARK_CORR_EXACT` | `0.75` | Strength at which one shared artifact alone makes an *exact* relationship. |
| `MAILSHARK_CORR_RESOLUTION` | `1` | Louvain resolution for clustering (>1 favours smaller clusters). |

The classification thresholds are part of the configuration hash stored with every result, and the
correlation parameters are recorded with every cluster, so a result can be traced to the settings
that produced it. Changing them affects new analyses only; re-analyse messages (or add evidence,
which re-runs correlation) to apply them to existing results.

### Intelligence and privacy

| Variable | Default | Meaning |
| --- | --- | --- |
| `MAILSHARK_INTEL_AUTOSYNC` | `true` | Scheduled downloads of the bulk feeds. |
| `MAILSHARK_ALLOW_ONLINE_LOOKUPS` | `true` | Server-wide permission for per-indicator lookups. Each case must still opt in (off by default). |
| `MAILSHARK_ALLOW_DKIM_DNS` | `true` | Fetch DKIM public keys over DNS during analysis, for cases that allow online lookups. |
| `MAILSHARK_BAZAAR_FULL` | `false` | Download the full MalwareBazaar hash export (~225 MB zip) instead of the 48-hour window. |
| `MAILSHARK_PHISHINGDB_LINKS` | `true` | Also download the Phishing.Database URL lists (~65 MB). |
| `MAILSHARK_MISP_FEED_SINCE` | `2019-01-01` | Oldest MISP feed events imported from CIRCL / botvrij. |
| `MAILSHARK_MISP_FEED_BATCH` | `400` | Events fetched per feed sync run (politeness; later runs continue). |

### Credentials for optional sources

Sources that need credentials stay visible as **not configured**, with the variable to set. None of
them is required.

| Variable | Source | How to obtain |
| --- | --- | --- |
| `OTX_API_KEY` | AlienVault OTX lookups | Free account at otx.alienvault.com → Settings → API key. Lookups work without a key at lower rate limits. |
| `VT_API_KEY` | VirusTotal lookups | Free community account at virustotal.com → API key (public API: 4 requests/minute, non-commercial terms). |
| `ABUSECH_AUTH_KEY` | MalwareBazaar API hash lookups | Free Auth-Key from auth.abuse.ch. |
| `PHISHTANK_APP_KEY` | PhishTank feed | Application key from phishtank.org (registration is intermittently closed by the operator). |
| `MISP_URL`, `MISP_API_KEY` | Your MISP instance | URL of your MISP server and an automation key of a user allowed to search attributes. TLS is always verified; for a private CA start Node with `NODE_EXTRA_CA_CERTS=/path/ca.pem`. |

Keys are only read from the environment, never stored in the database or shown in the interface.

## Using it

1. **Create a case** (Cases → New case). Leave *online lookups* off unless the case may disclose
   indicators to third parties.
2. **Add evidence** (Evidence). Drop up to 100 files. Each file gets SHA-256, SHA-1 and MD5 at intake
   and is stored unchanged before any parsing; containers (mbox, emlx, msg) are expanded into
   messages that keep a byte offset back to the file. Rejections (empty, oversized, not email,
   corrupt container) are recorded per file with a reason; nothing else in the batch is affected.
3. **Watch processing** on the Evidence or Overview page. A restart resumes interrupted work.
4. **Triage** in Messages: a packet-analyser layout with the message list, the analysis tree
   (assessment → external intelligence → observed evidence) and the raw message. Clicking a
   finding's affected component highlights the bytes it refers to.
5. **Correlate**: Campaigns lists local clusters (with what stays constant and what rotates) and
   associations with externally reported events; Graph shows the entities and their links.
6. **Report**: Reports produces JSON (validated against `/api/schema/report`), Markdown and DOCX
   from one report build, with a data hash shared by all renderings.

## Development

| Command | Purpose |
| --- | --- |
| `npm run typecheck` | TypeScript over engine, extension, platform and tests. |
| `npx vitest run platform/test` | Platform tests (API end to end, evidence, intelligence, correlation). |
| `npm test` | All tests (engine, extension, platform). |
| `node scripts/platform-build.mjs --dev --watch` | Rebuild on change. |
| `node scripts/eval/run.mjs forensic` | Classification metrics on the labelled corpora (see VALIDATION.md). |
| `node scripts/eval/run.mjs correlation --intel-db <intel.db>` | Correlation strategy benchmark. |
| `MS_USER=… MS_PASSWORD=… node scripts/platform-load.mjs` | Load and robustness run against a live server. |

## HTTP API

All endpoints are under `/api`, return JSON, and require a session cookie except `health`, `setup`,
`auth/login`, `auth/session` and `auth/logout`. Mutating requests require the `x-csrf-token` header
returned by login. Errors are `{ "error": { "code", "message", "details"? } }`.

| Area | Endpoints |
| --- | --- |
| System | `GET health` · `GET catalog` (finding catalogue, live thresholds) · `GET schema/report` |
| Session | `POST setup` · `POST auth/login` · `POST auth/logout` · `GET auth/session` · `POST auth/password` |
| Users | `GET/POST users` · `PATCH users/:id` · `POST users/:id/password` |
| Cases | `GET/POST cases` · `GET/PATCH/DELETE cases/:id` · `GET/POST cases/:id/members` · `DELETE cases/:id/members/:uid` |
| Evidence | `POST cases/:id/batches` (multipart, ≤100 files) · `GET cases/:id/batches` · `GET cases/:id/evidence` · `GET cases/:id/evidence/:eid` · `POST …/verify` · `GET …/download` |
| Analysis | `GET cases/:id/progress` · `GET cases/:id/stats` · `GET cases/:id/messages` (filters: class, status, severity, q, cluster, indicator, finding, batch, evidence, intel; sort, page) · `GET cases/:id/messages/:mid` · `GET …/raw` · `POST …/reanalyze` · `GET …/history` · `GET cases/:id/search` |
| Indicators | `GET cases/:id/indicators` · `GET cases/:id/indicators/:iid` · `POST cases/:id/lookups` |
| Campaigns | `GET cases/:id/clusters` · `GET cases/:id/clusters/:cid` · `GET cases/:id/external-campaigns` · `GET intel/events/:source/:eventId` |
| Graph | `GET cases/:id/graph` (types, classes, severities, sources, from, to, minEdge, similarity, minDegree, focus, depth, q, cluster, limit) |
| Reports | `POST cases/:id/reports` (`format` or `formats[]`, scope case/batch/messages) · `GET cases/:id/reports` · `GET …/:rid/download` |
| Intelligence | `GET intel/sources` · `GET intel/sources/:sid/history` · `POST intel/sources/:sid/sync` · `PATCH intel/sources/:sid` |
| Activity | `GET cases/:id/activity` · `GET admin/audit` · `GET admin/audit/verify` · `GET admin/system` |
