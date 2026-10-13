# Campaign intelligence

How the platform relates messages to each other inside a case, how it relates them to externally
reported activity, and which intelligence sources it uses, each evaluated on its own terms.
Measured results are in [VALIDATION.md](VALIDATION.md).

## 1. Three kinds of statement, kept apart

| Statement | Where it comes from | How it is shown |
| --- | --- | --- |
| **Exact relationship** | Two messages share one artifact specific enough to link them on its own: identical attachment (SHA-256), the same tokenised URL, the same Reply-To mailbox, phone number, wallet, authenticated sending account or bulk-mail campaign id (strength ≥ `MAILSHARK_CORR_EXACT`, default 0.75). | Red solid edge in the graph; "exact" badge with the shared artifact. |
| **Probable relationship** | Several weaker shared indicators and/or high fingerprint similarity combine above `MAILSHARK_CORR_EDGE` (default 0.6), without a single decisive artifact. | Amber dashed edge; the shared indicators and per-layer similarities are listed. |
| **External association** | An indicator of the message appears in a record published by an intelligence source. *Reported* when a strong, specific indicator is listed in a named event; *possible* when only weak overlaps exist (parent domain, IP, subject, file name) or when the record is a generic indicator dump. | Purple; always labelled with the source, the match type and the snapshot. Never merged into local clusters. |

None of these is an attribution to an actor. A cluster says "these messages were very probably
produced by the same operation"; an external association says "a third party has reported this
indicator in this context".

## 2. Local correlation (inside a case)

Implemented in `platform/server/correlation/engine.ts`; runs in a worker after every batch has been
analysed (debounced per case), and after online lookups that found something new.

### 2.1 Indicator evidence

Every indicator the engine extracts has a type and a **role** (`from`, `reply-to`, `link`,
`link-host`, `attachment`, `origin-ip`, `client-ip`, …). Each role maps to a *family* with a base
strength (live values: `GET /api/catalog`, also shown under *Method & limits* in the app):

| Family | Base | Family | Base |
| --- | --- | --- | --- |
| Identical attachment | 0.95 | Same phone number | 0.90 |
| Same cryptocurrency wallet | 0.95 | Same bulk-mail campaign id | 0.90 |
| Same tokenised URL | 0.85 | Same Reply-To mailbox | 0.85 |
| Same authenticated sending account | 0.85 | Same submitting client IP | 0.80 |
| Same link host | 0.60 | Same sender address | 0.55 |
| Same link (generic URL) | 0.55 | Same sending IP | 0.50 |
| Same link domain | 0.45 | Same envelope sender | 0.40 |
| Same sender domain | 0.35 | Same DKIM signing domain | 0.30 |

The base is then reduced by **specificity**: popularity of the registrable domain (Tranco rank),
shared platforms (free hosting, URL shorteners, ESP click trackers, free-mail domains), and fan-out
(an indicator shared by many otherwise unrelated messages, or by many different senders, is less
specific). Every discount is recorded next to the indicator, so a reviewer can see why "same link
domain docs.google.com" contributed almost nothing. Per-pair indicator evidence is combined with
noisy-OR: `1 − Π(1 − sᵢ)`.

### 2.2 Fingerprint similarity

The engine's layered similarity (`engine/src/campaign/similarity.ts`) compares content (MinHash,
SimHash, HTML skeleton), link templates and kit paths, attachment structure, infrastructure, sender
patterns, semantics (intent, brand, requested actions) and delivery time. Before comparing,
infrastructure that belongs to large providers is **neutralised**: when a message was sent through a
free-mail provider, an ESP or a large shared sending network, its origin network, DKIM domain and
similar fields describe the provider, not the sender, and are removed. This was introduced after
benign Gmail newsletters clustered on Google infrastructure during development.

### 2.3 Edges and clusters

`score = 1 − (1 − indicators) × (1 − similarity)`. A pair is linked when one artifact is decisive
(exact) or the score reaches the edge threshold (probable). Clusters are Louvain communities on the
evidence-weighted graph (deterministic order; resolution `MAILSHARK_CORR_RESOLUTION`). Each cluster
records its members with a membership strength, cohesion, density, the number of exact edges, its
time span, and a **profile**: invariants (what every member shares: sender pattern, kit path,
mailer, landing template) and rotated attributes (what the operator changes between messages).
A cluster is labelled *threat*, *mixed* or *bulk* from the classes of its members.

Candidate pairs come from an inverted index over indicators and fingerprint keys (keys shared by more
than `maxKeyFanout = 200` messages are not used to propose candidates), so cost grows with the number
of related pairs, not with n².

### 2.4 Strategy choice

The combination of specificity-weighted indicators and neutralised similarity was compared with
simpler strategies on a benchmark with known ground truth (VALIDATION.md §3). Summary: exact
artifacts alone are precise but find only 0–9 % of related pairs, because kits rotate tokens and
domains; indicators without specificity weighting pull legitimate and unrelated messages into
campaign clusters; similarity alone misses campaigns whose content drifts; the combination was best
on both seed sets. Louvain and plain connected components gave identical clusters on that benchmark,
so the benchmark does not show an advantage of Louvain; it is kept because it does not chain clusters
through single bridging edges, which connected components would.

## 3. External correlation

Implemented in `platform/server/correlation/external.ts`. For every observed indicator the store is
queried (all locally, see §4):

- **Listings**: is the URL, host (and its parents), IP (exact or inside a listed range), hash,
  e-mail address, phone number or wallet listed by a feed? Matches carry the match type (`exact`,
  `host`, `parent-domain`, `cidr`, `listed-url-on-host`, …) and a strength. Listings of popular
  domains and shared platforms are kept as *context only* (strength 0) and never make a message
  malicious; Tor exit addresses are context, not a verdict.
- **Events**: is the indicator part of a documented event (MISP feeds, OTX pulses, your MISP)? The
  event becomes an external association with the overlapping indicators and a rationale.
  - Records that a source publishes as generated **series** (for example daily
    "Phishing | Oct 13, 2026 | Part 182/566" pulses) are merged into one association listing all
    record ids.
  - Records whose name only describes a category of data (no actor, lure or operation) are flagged
    **generic** and can at most be a *possible* association: they show that the indicator is known
    to the source, not which campaign it belongs to. This rule was added after a live OTX lookup
    returned 25 near-identical daily dump pulses for one phishing domain, which had all been reported
    as campaign associations.

Every analysis stores the intelligence **snapshot id** it was matched against; every match stores
the record it matched. A later feed update therefore never silently changes what a past report said.

## 4. Sources

<a id="sources"></a>All bulk feeds are downloaded on a schedule (`MAILSHARK_INTEL_AUTOSYNC`) by an
isolated worker and matched **locally**: case data never leaves the server for them. Each connector
declares the exact hosts it may contact; the HTTP client refuses any other host, including through
redirects, refuses non-HTTPS URLs and caps response size. Conditional requests (ETag /
Last-Modified) avoid re-downloading unchanged data. A failing source keeps its previous data and
shows *unavailable* with the error; a source whose last success is older than three refresh intervals
(at least 48 hours), or whose latest attempt failed, shows *stale*.

Online **lookups** send one indicator value to a third party. They run only when the server allows
them (`MAILSHARK_ALLOW_ONLINE_LOOKUPS`) *and* a case lead has enabled them for the case, always on an
explicit request by an investigator, through per-source rate limiters, with results cached and the
request recorded in the audit log.

"Live" below means the connector was run against the real service from this development machine on
the date given, with the result shown. "Mocked" means the parser was tested against a response
written in the provider's documented format, not a recorded response.

| Source | Format and access | Fields used | Update | Licence / terms | Attribution quality | Limits | Verified |
| --- | --- | --- | --- | --- | --- | --- | --- |
| **Tranco** top 1M | CSV in zip, public | rank, domain | weekly (connector: 168 h) | free for research and commercial use | none (enrichment) | — | Live 2026-10-12: 1,000,000 domains |
| **iptoasn** via ip-location-db (jsDelivr) | CSV ranges, public | IP range, ASN, AS name | weekly (168 h) | PDDL | none (enrichment) | — | Live 2026-10-12: 489,436 ranges |
| **URLhaus** | CSV dump in zip, public | URL, threat, tags, status, dates, link | 6 h | abuse.ch fair use (commercial use may need a subscription) | malware family via tags | — | Live 2026-10-12: 73,321 URLs; mocked parser test |
| **URLhaus host file** | text, public | host | 6 h | abuse.ch fair use | indicator only | — | Live 2026-10-12: 416 hosts |
| **ThreatFox** | JSON export in zip, public | IOC, type, threat type, malware, confidence, first/last seen, reference | 6 h | abuse.ch fair use | malware family + confidence | — | Live 2026-10-12: 111,611 IOCs (53 popular-site entries dropped); mocked parser test |
| **MalwareBazaar** | CSV export (48 h window, or full with `MAILSHARK_BAZAAR_FULL`), public | SHA-256/SHA-1/MD5, signature, file name, type | 4 h | abuse.ch fair use | malware family (signature) | full export ≈225 MB | Live 2026-10-12: 2,838 samples (48 h window, kept across syncs) |
| **Feodo Tracker** | JSON, public | C2 IP, port, malware, ASN, dates | 6 h | abuse.ch fair use | malware family | — | Live 2026-10-12: 5 C2 IPs |
| **OpenPhish** community | text (one URL per line), public, now hosted on GitHub | URL | 12 h | OpenPhish terms (commercial use limited) | indicator only (no brand in the free feed) | — | Live 2026-10-13: 300 URLs. The first live run failed: openphish.com now redirects to raw.githubusercontent.com, which the allowlist correctly refused; the connector now fetches the GitHub URL. Mocked test. |
| **Phishing.Database** | text lists on GitHub, public | domain, URL | 24 h | MIT | indicator only | URL lists ≈65 MB | Live 2026-10-12: 1,175,476 entries (185 popular-site entries dropped) |
| **Spamhaus DROP** | JSON (NDJSON), public | CIDR, SBL id | 24 h | free use, no redistribution of the list | indicator only (strong context) | — | Live 2026-10-12: 1,677 netblocks |
| **Tor exit list** | text, public | IP | 6 h | public Tor Project data | context only, never a verdict | — | Live attempt 2026-10-12 **failed** (connection reset by the network); mocked parser test only |
| **PhishTank** | JSON, free application key | URL, target brand, verification time, detail page | 6 h | PhishTank terms | indicator + targeted brand | key registration often closed | **Not tested live** (no key); mocked parser test |
| **CIRCL OSINT** (MISP feed) | MISP feed: manifest + event JSON, public | event name, org, date, tags, attributes (URL, domain, IP, e-mail, subject, file name, hash, wallet, phone) | 12 h, batched (`MAILSHARK_MISP_FEED_BATCH`) | TLP:CLEAR OSINT | named events (campaign reports) | polite batches; first import takes several runs | Live 2026-10-12: 290,029 attributes from 399 events in the first run (254 events left for later runs; one event request timed out and is retried); mocked test |
| **botvrij.eu** (MISP feed) | as CIRCL | as CIRCL | 12 h | TLP:CLEAR OSINT | named events | — | Live 2026-10-12: 21,239 attributes, 290 events |
| **AlienVault OTX** | REST, key optional | pulses: name, author, dates, tags, adversary, malware families, references | per lookup | OTX terms | from named campaigns to generic daily dumps (generic ones are detected) | 60 req/min client-side | Live 2026-10-13, without key: domain lookup returned 50 pulses; the result exposed the generic-series problem (§3), fixed and tested |
| **VirusTotal** | REST v3, free key | engine statistics, threat label, tags, dates | per lookup | public API: non-commercial, 4 req/min | malware family label (vendor consensus) | 4 req/min client-side | **Not tested live** (no key); mocked test (found and 404) |
| **MISP instance** (yours) | REST `attributes/restSearch`, API key | events containing the value, tags | per lookup | your sharing groups / TLP | as good as your MISP | 60 req/min client-side | **Not tested live** (no instance); mocked test |
| **MalwareBazaar API** | REST, free Auth-Key | signature, first/last seen, file name, delivery method, tags | per lookup | abuse.ch fair use | malware family | 30 req/min client-side | **Not tested live** (no key); mocked test |

### What the sources do *not* give

- No free source used here names threat actors reliably; malware families (ThreatFox, MalwareBazaar,
  URLhaus tags) and named events (MISP feeds, OTX) are the strongest attribution available, and they
  are third-party assessments.
- Phishing URL feeds are short-lived windows: a URL that is no longer listed was not necessarily
  safe. The platform keeps what each analysis matched, with the snapshot.
- Coverage is uneven: phishing landing pages and malware distribution are well covered; BEC,
  call-back scams and extortion (which often contain no URL) mostly are not. For those, local
  correlation (shared Reply-To mailboxes, phone numbers, wallets) matters more than feeds.

### Adding a source

A connector is a declaration in `platform/server/intel/sources.ts`: id, provider, kind (feed,
enrichment, lookup), licence, what it provides, attribution quality, access, refresh interval, the
exact hosts it may contact, required configuration keys, and a `sync` (bulk) or `lookup` function
that normalises records into the store. Add a mocked parser test in `platform/test/intel.test.ts` and
state in this table whether it was verified live.
