# Validation

What was tested, how, and what came out, including what went wrong and what was **not** tested.
Raw outputs are in [`results/`](results/). Every number below was measured on 2026-10-12/13 on one
development machine:
- AMD Ryzen 7 7735HS (16 logical CPUs), 16 GB RAM
- Windows 11 (10.0.26200), Node 22.19.0
- platform 1.0.0, engine 1.2.0

## 1. Automated tests

`npx vitest run`: **142 tests in 9 files, all passing** (engine, extension and platform).

The platform tests drive the real HTTP API in-process (Fastify `inject`), the real worker pool, the
SQLite databases and the evidence store:

| File | Tests | Covers |
| --- | --- | --- |
| `platform/test/api.test.ts` | 28 | Setup token; login, account lockout after 8 failures (also for the right password), CSRF and security headers; mixed batch intake with per-file outcomes; processing to completion; classes consistent with the fixtures; message investigation view with provenance and documented findings; mbox expansion with offsets and duplicate linking; campaign clustering; graph integrity (every edge points at existing nodes, explicit hidden counts); indicators; schema-valid JSON report with verifying hash; Markdown and DOCX consistency and defanging; multi-format rendering from one report build; case statistics; method catalogue; graph severity filter; indicator intelligence filter; case isolation (404 for non-members, read-only roles); **101 files rejected atomically, exactly 100 accepted**; evidence and audit-chain verification; legal hold; **restart recovery**; **failure isolation** (timeout, parser limits not retried) |
| `platform/test/evidence.test.ts` | 12 | Format detection by content (including truncated files and header blocks longer than the detection window), structured rejections, container expansion, byte-identical originals, content-addressed store, size limit without partial files, tamper detection, path-traversal-safe blob names |
| `platform/test/intel.test.ts` | 22 | Normalisation; store lookups (URL, host and parents, IP and CIDR, events); popular-domain suppression; snapshot ids; every connector's parser (URLhaus, ThreatFox, MISP feeds, OpenPhish, PhishTank, Tor, OTX, VirusTotal, MISP instance, MalwareBazaar API) against payloads in the providers' documented formats; failing source keeps its data; **SSRF guard** (allowlist, also through redirects); generated record series and generic dumps |
| `platform/test/correlation.test.ts` | 5 | Specificity discounts; a rotating phishing kit links; an identical attachment links otherwise unrelated messages; benign newsletters on shared infrastructure do not link; Louvain properties |
| `engine/test/forensics.test.ts` | 20 | DKIM (RFC 8463 test vectors), header forensics, indicators, coverage, classification, link-analysis cap |

Typecheck (`tsc --noEmit`) passes. The extension still builds and passes `web-ext lint
--warnings-as-errors` with 0 errors, 0 notices and 0 warnings.

## 2. Detection on labelled corpora

### 2.1 Data and provenance

| Corpus | Label | Messages | Provenance and licence |
| --- | --- | --- | --- |
| Nazario phishing corpus 2015–2025 (mbox per year) | phishing | 3,466 | Jose Nazario, monkey.org/~jose/phishing, CC BY 4.0 |
| phishing_pot | phishing | 8,612 | rf-peixoto/phishing_pot (GitHub), honeypot-collected, anonymised by the contributors |
| SpamAssassin public corpus: easy_ham, easy_ham_2, hard_ham | legitimate | 4,150 | Apache SpamAssassin project, 2002–2003 |

The corpora are not in the repository (privacy and licensing); `scripts/eval/corpus.ts` documents
the expected layout. No sample was unreadable in this run (antivirus quarantine is counted if it
happens).

**Split.** Each message is assigned by the first byte of its SHA-256: ≈70 % *tune*, ≈30 %
*holdout*, independent of file order. The classification thresholds (35 / 70 / coverage 0.5) predate
this report and were not changed using either split. The one rule change made during this work
(§2.3) was designed on the tune split only and then checked on the holdout. The engine heuristics
were, however, developed over time with access to all three corpora, so the holdout guards against
threshold tuning, not against design-time exposure.

### 2.2 Results (engine 1.2.0, `node scripts/eval/run.mjs forensic`)

| Metric | All (16,228) | Tune (11,261) | Holdout (4,967) |
| --- | --- | --- | --- |
| Phishing flagged (malicious or suspicious): recall | 74.8 % | 74.8 % | 75.0 % |
| Legitimate flagged: false-positive rate | 1.0 % | 0.9 % | 1.1 % |
| False-negative rate | 25.2 % | 25.2 % | 25.0 % |
| Precision of flagged | 99.6 % | 99.6 % | 99.5 % |
| Precision of *malicious* | 99.8 % | 99.8 % | 99.7 % |
| Phishing classified *malicious* | 52.5 % | 52.3 % | 53.0 % |
| Legitimate classified *malicious* | 0.3 % (12) | 0.2 % | 0.4 % |
| Inconclusive (phishing / legitimate) | 0.1 % / 0 % | 0 % / 0 % | 0.1 % / 0 % |
| Analysis failures | 0 | 0 | 0 |

Confusion (all): phishing → malicious 6,340 · suspicious 2,698 · benign 3,033 · inconclusive 7;
legitimate → benign 4,110 · suspicious 28 · malicious 12.

Per corpus: Nazario 86.6 % flagged (71.5 % malicious); phishing_pot 70.1 % flagged (44.9 %
malicious); SpamAssassin 1.0 % flagged.

### 2.3 Confidence

Share of calls that were correct, by class and confidence (holdout in brackets):

| Call | n | Correct |
| --- | --- | --- |
| malicious, high | 5,355 | 100 % (100 %) |
| malicious, medium | 996 | 99.0 % (98.5 %) |
| benign, high | 3,779 | 85.4 % (85.5 %) |
| benign, medium | 2,711 | 28.4 % (28.1 %) |
| benign, low | 653 | 17.2 % (15.9 %) |

**Correction made during validation.** With engine 1.1 (rule: "benign is high when the margin is
≥ 20, coverage ≥ 0.8 and no medium-or-higher finding"), *benign, high* was correct for only
**73.2 %** of 5,050 calls. "No findings" was being treated as strong evidence. An analysis on the
tune split (`scripts/eval/benign-analysis.ts`) showed:
- Any low- or medium-severity finding appeared in 16 % of the legitimate benign calls but in 75 % of
  the missed phishing.
- Authentication could **not** be used: none of the 2002-era legitimate messages carry
  Authentication-Results, while 91 % of the missed phishing does. An authentication rule would
  learn the corpus' era, not legitimacy.

Engine 1.2 requires *no* risk finding above informational for *benign, high*. Results:
- Correctness of *benign, high* rose to 85.4 % (holdout 85.5 %).
- The share of all phishing that receives *benign, high* fell from ≈11 % to 4.6 %.
- The share of legitimate mail receiving it fell from ≈89 % to 77.8 %.
- No class changed, only confidence.

**Benign precision depends on prevalence.** The corpus is 74 % phishing, which no real mailbox is.
The rates conditioned on the true label are 77.8 % of legitimate mail and 4.6 % of phishing receiving
*benign, high*. From these, *benign, high* would be correct for **99.9 %** of calls if 1 % of the
input were phishing, and **99.3 %** at 10 %. These are derived figures, not measured on such an
input.

Suspicious calls are deliberately never *high*; they are review requests.

### 2.4 Known biases

- The legitimate corpus is from 2002–2003: no SPF/DKIM/DMARC, older HTML, mailing-list heavy. The
  false-positive rate on modern authenticated legitimate mail (newsletters with tracking links,
  transactional mail from ESPs, internal mail) has **not been measured**.
- The phishing corpora come from honeypots and one researcher's inbox; their mix of lures and
  infrastructure is not that of any particular organisation.
- 25 % of the phishing is missed. Spot checks of misses (development work) found mainly link-free
  scams, authenticated messages from compromised or look-alike accounts, and non-English lures.

### 2.5 Extension

The extension's three-way verdict on the same corpora is unchanged by this work: 74.8 % of phishing
flagged at a 1.0 % false-positive rate (its risk score and thresholds are the engine's).

## 3. Campaign correlation benchmark

`node scripts/eval/run.mjs correlation --campaigns 60 --intel-db <intel.db>`
(results: [`results/correlation-eval.json`](results/correlation-eval.json)).

### 3.1 Design

No public corpus labels phishing campaigns, so campaigns were generated from **real** phishing:
1. **Seeds.** 120 phishing_pot messages, selected in hash order and required to be mutually
   independent: no shared sender organisation (free-mail excepted), uncommon link domain (Tranco rank
   > 20,000 or unranked), attachment, Reply-To organisation or subject template. 209 candidates were
   skipped as related.
2. **Variants.** Each seed was parsed and re-sent as 2–8 variants. Every variant rotated recipient,
   Message-ID, date, sending IP and the tokens in URLs and subject numbers. Per campaign at random:
   - sender domain: kept 39 / rotated 58 / free-mail 23
   - landing domain: rotated in 53 campaigns
   - sending network: same /24 in 59
   - content drift: none 37 / light 48 / heavy 35 (light: numbers changed and a sentence added;
     heavy: also ~25 % of words replaced)
   - attachment bytes: polymorphic in 2 (few seeds carried attachments)
   - mailer header: kept or dropped
3. **Confounders.** 180 further independent phishing_pot messages and 240 SpamAssassin legitimate
   messages, all unmodified.
4. **Splits.** Two disjoint halves of the seeds, A and B (60 campaigns each; 301 and 337 variants;
   90 phishing and 120 legitimate confounders each).
5. **Labels.** A pair is positive if both messages are variants of the same seed, and negative if one
   is a variant and the other is anything not generated from that seed. Pairs of two confounders are
   **not scored**, because they can genuinely be related (same mailing list, same actor).
6. **Metrics.** Pairwise precision, recall and F1 for edges and for same-cluster membership; the
   adjusted Rand index over variants; and the number of confounders placed in a cluster with
   campaign variants.
7. **Environment.** Tranco popularity and ASN data from the live-synchronised intelligence store.

### 3.2 Strategies compared

| Strategy | A: cluster P | R | F1 | ARI | confounders pulled in | B: cluster P | R | F1 | ARI | confounders |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Exact artifacts only (components) | 1.000 | 0.066 | 0.124 | 0.122 | 0 | 1.000 | 0.001 | 0.002 | 0.002 | 0 |
| Indicators, no specificity weighting | 0.528 | 0.781 | 0.630 | 0.755 | 19 | 0.554 | 0.781 | 0.648 | 0.719 | 11 |
| Indicators with specificity weighting | 1.000 | 0.467 | 0.637 | 0.633 | 0 | 0.952 | 0.469 | 0.629 | 0.625 | 0 |
| Similarity only | 1.000 | 0.744 | 0.853 | 0.851 | 0 | 1.000 | 0.848 | 0.918 | 0.916 | 0 |
| Combined, connected components | 1.000 | 0.863 | 0.926 | 0.925 | 0 | 0.976 | 0.966 | 0.971 | 0.971 | 0 |
| **Combined, Louvain (platform default)** | 1.000 | 0.863 | 0.926 | 0.925 | 0 | 0.976 | 0.966 | 0.971 | 0.971 | 0 |

Readings:
- Kits rotate tokens and domains, so exact shared artifacts almost never link variants.
- Raw indicator matching links the most pairs among the indicator-only strategies but pulls 11–19
  confounders into campaign clusters. Specificity weighting removes that contamination at a cost in
  recall.
- Similarity alone misses campaigns with heavy content drift.
- The combination is best on both seed sets.
- Louvain and connected components produced identical clusters here, because no false bridging edges
  occurred. The benchmark therefore does not demonstrate an advantage of Louvain.

### 3.3 Threshold sensitivity (combined, Louvain)

| Edge threshold | 0.50 | 0.55 | **0.60** | 0.65 | 0.70 | 0.75 | 0.80 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Cluster F1, A | 0.967 | 0.948 | **0.926** | 0.911 | 0.893 | 0.882 | 0.852 |
| Cluster F1, B | 0.980 | 0.978 | **0.971** | 0.959 | 0.932 | 0.901 | 0.885 |
| Confounders pulled in (A / B) | 0 / 0 | 0 / 0 | 0 / 0 | 0 / 0 | 0 / 0 | 0 / 0 | 0 / 0 |

Lower thresholds scored better on this benchmark without contamination. The default stays at 0.60:
- The benchmark is synthetic and contains no deliberately similar but unrelated campaigns (the
  hardest real case).
- Precision errors in an investigation (merging unrelated operations) are costlier than missed links,
  which the analyst can add by focusing on a message.

`MAILSHARK_CORR_EDGE` lets a team choose otherwise.

### 3.4 What the first benchmark run got wrong

The first run did not require seeds to be independent. It reported many false-positive edges between
"different" campaigns, mostly through shared link hosts and sender domains. They were real: phishing_pot
contains many copies of the same real campaigns, so the labels were wrong, not the correlator.
The independence filter above was added before any of the reported numbers were produced. An earlier
version also left message bodies identical across variants, which made similarity alone look almost
perfect (cluster F1 0.98); content drift was added for that reason.

## 4. Platform performance and robustness

`MS_USER=… MS_PASSWORD=… node scripts/platform-load.mjs` against a running server with 8 analysis
workers (default for this machine) and the live intelligence store
([`results/platform-load.json`](results/platform-load.json)).

| Scenario | Result |
| --- | --- |
| One batch of 100 real phishing files (5.3 MB) | Upload accepted in 0.36 s (201, 100 accepted); all 100 analysed and the case correlated 5.6 s later (≈17 messages/s end to end) |
| Four concurrent batches of 25 files in four cases | All four 201; 100 messages analysed and correlated in 2.9 s wall time; 0 failures |
| 60 MB file (limit 50 MB) uploaded with two valid files | Batch 201; oversized file `rejected / file-too-large`, bytes not kept; the two valid files analysed |
| 101 files in one batch | 413 `too-many-files`, nothing stored (API test) |
| Mixed 94-file intake (fixtures, real phishing and ham, a 101-message Nazario mbox, three junk files, one duplicate) | 90 accepted, 3 rejected with codes `empty-file`, `binary-not-email`, `unsupported-format`, 1 duplicate linked to its original; 190 messages analysed and correlated in 7.6 s |

**Malformed and hostile inputs** (one batch; every item reached a terminal state; the server stayed
healthy):

| Input | Outcome |
| --- | --- |
| First half of a valid message (cut inside the headers) | analysed (*inconclusive*). **Fixed during validation:** first rejected as `unsupported-format`, because detection rejected a header block whose last line was cut off; the same bug would have rejected messages whose header block exceeds the 8 KB detection window. |
| MIME nesting 300 levels deep | failed alone, `mime-nesting-limit`, not retried. **Fixed during validation:** first failed with a generic code after three pointless retries. |
| One 2 MB header line | failed alone, `header-size-limit`, not retried (same fix) |
| 20,000 header fields | analysed (*inconclusive*) |
| Invalid base64 body | analysed (*inconclusive*) |
| 200 MB zip bomb as attachment (≈200 KB compressed) | analysed in 44 ms (*inconclusive*); bounded archive inspection |
| 30,000 distinct links | analysed (*inconclusive*, links layer partial, integrity finding "Not every link was analysed"). **Fixed during validation:** took 43 s (≈1 ms per link) before the 1,000-link analysis cap; now 1.7 s. |
| 20,000 `<script>` and `<iframe>` elements | analysed; never executed or rendered |
| 100 KB of NUL bytes after headers | rejected `binary-not-email` |
| UTF-16 file | rejected `unsupported-encoding` |
| mbox separator followed by binary garbage | rejected `binary-not-email` |
| OLE file that is not an Outlook item | rejected `ole-not-msg` |

Before the fixes this batch took 45 s; after them 5.1 s.

**Interruption and recovery** (API tests): jobs left *running* by a simulated crash are re-queued at
start-up and complete; the event history shows `resumed-after-interruption`. A message that exceeds
the analysis timeout fails alone with code `timeout` after two recorded retries while the rest of the
batch completes.

**Unavailable intelligence.** The tests run without any intelligence store; analysis and correlation
complete and report no matches. A failing source keeps its previous data and shows the error
(unit test, and observed live with the Tor exit list and the first OpenPhish run).

## 5. Web client

Verified by hand in the Chromium-based browser pane against the running server and the case data of
§4, at 1440 × 900 and at 375 × 812 (phone):
- first-run setup with the console token
- the case list and overview (KPIs, timeline, top findings, clusters, intelligence-listed indicators,
  sender domains)
- evidence intake status and the chain-of-custody drawer, including integrity verification
- the message workspace: list, analysis tree, raw view; clicking an affected component (`link[0]`)
  scrolled to and highlighted the quoted-printable line containing it
- the concise benign summary
- indicators with the intelligence filter and the indicator drawer
- campaigns
- the graph: 600 of 811 entities drawn with the hidden-entity banner; selection, inspector and
  incremental expansion (600 → 603 entities)
- reports in three formats sharing one data hash
- intelligence sources, including a live OpenPhish sync started from the page
- administration, account, method & limits
- light theme
- no horizontal page scroll at phone width; no console errors

Defects found by this walk-through and fixed:
- Table columns collapsed: fixed table layout replaced a `max-width: 0` hack.
- The verdict header squeezed the subject.
- The indicator *listed by intelligence* filter returned unlisted indicators: an SQL alias collided
  with a message column in `HAVING`.
- The indicator drawer hid matches made on the URL's host.
- Opening the inspector pushed the selected node off-screen.
- On phones the brand overlapped the status and the navigation labels collided.

`tests/e2e_platform_firefox.py` automates this flow in Firefox/Gecko (setup, case creation, upload
through the file input, workspace, highlighting, keyboard navigation, graph, reports, theme, phone
width, CSP/console errors). **It has not been run**: the only Gecko browser installed (Zen) needs a
geckodriver binary, and none was available.

## 6. Intelligence

Live synchronisation and lookup results per source are in [CAMPAIGNS.md](CAMPAIGNS.md#sources).
Highlights:
- 12 feed and enrichment sources synchronised live (≈3.17 million records in total), OpenPhish after a fix.
- The Tor list failed from this network.
- A live OTX lookup (no key) returned 50 pulses for a phishing domain from the corpus. This exposed
  generic daily dump pulses being reported as campaign associations, which was fixed (series merged,
  generic records at most *possible*) and covered by tests.

## 7. Not validated

Stated explicitly so that nothing above is read as covering it:

- The Firefox/Gecko end-to-end UI test (written, not run).
- VirusTotal, PhishTank, MalwareBazaar API and a MISP instance against the live services (mocked
  only); the Tor exit list live.
- Campaign correlation on real campaign-labelled data (none available); deliberately similar but
  unrelated campaigns.
- False-positive rate on modern legitimate mail.
- Long-running stability (soak), memory growth over days, and more than four concurrent uploaders.
- Very large containers near the 10,000-message mbox limit, and batches near the 1 GB batch limit.
- DOCX reports opened in Word or LibreOffice (only the document XML was checked).
- Accessibility audit (keyboard paths and ARIA roles were implemented, not audited).
- Independent security testing (penetration test). The security controls in DESIGN.md §8 are
  covered by the automated tests listed in §1, not by an external assessment.
- Any forensic standard (see LIMITATIONS.md).

## 8. Reproducing

```bash
npx vitest run
```

```bash
node scripts/eval/run.mjs forensic
```

```bash
node scripts/eval/run.mjs correlation --campaigns 60 --intel-db data/intel.db
```

```bash
npm run platform:build
```

```bash
lab/.venv/Scripts/python tests/e2e_platform_firefox.py
```

The load script needs a running server and an account: `MAILSHARK_URL`, `MS_USER` and
`MS_PASSWORD`, then `node scripts/platform-load.mjs`.
