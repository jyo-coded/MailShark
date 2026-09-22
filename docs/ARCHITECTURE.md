# Architecture

MailShark has three layers:
- a **pure analysis engine**
- a **Firefox add-on** that feeds it messages and presents its results
- **offline tooling** (feed compiler, accuracy harness, forensic lab)

Only the add-on runs on users' machines, and it has no server component.

```
 Gmail tab (mail.google.com)                     Add-on background page (event page)
 ┌──────────────────────────────────┐            ┌─────────────────────────────────────────┐
 │ content.js                       │  raw MIME  │ pipeline.ts                             │
 │  • detects the opened message    │ ─────────► │  analyzeEmail()  ◄── engine/src          │
 │  • fetches ?view=att&th=<id>     │            │  correlate()     ◄── campaign/*          │
 │    (Gmail "Show original" data)  │ ◄───────── │  IndexedDB: reports, campaigns, senders │
 │  • banner, inspector, link guard,│  summary / │  feeds.ts: Bloom filters (12 h refresh) │
 │    inbox radar (closed shadow    │  report    │  qr.ts: image → jsQR                    │
 │    roots, no page script access) │            └─────────────────────────────────────────┘
 └──────────────────────────────────┘                          ▲
                                                               │ runtime messages
                                        lab.html / popup.html / welcome.html (Preact)
```

## Acquisition

Gmail's web client can return any message's original RFC 5322 source from a same-origin URL: `?view=att&th=<legacy-message-id>&attid=0&disp=comp&safe=1&zw`. This is the data behind *Show original*.

The content script reads the legacy id from the open message's `data-legacy-message-id` and fetches that URL with the user's existing session. This needs no OAuth scope, no Google API project and no download.

Firefox content-script `fetch` returns objects from the page compartment. The body is therefore read with `FileReader.readAsBinaryString` to get a plain string, which is handed to the background page as Latin-1 bytes.

All Gmail-specific DOM knowledge lives in `extension/src/content/gmail.ts`, so a Gmail change is a one-file fix.

## Engine (`engine/src`)

`analyzeEmail(bytes, options)` returns a `Report` (schema `mailshark.report/1`). The engine is plain TypeScript with no DOM and no network, so the same code runs in the add-on, in Node for the accuracy harness, and in the unit tests.

1. **Parse:** `postal-mime` for MIME structure, plus a raw header reader (`mime/raw.ts`) that keeps order, duplicates and folding, which parsers normalise away.
2. **Analyzers** (`analyzers/`):
   - `route`: trusted hand-off hop, origin IP
   - `auth`: trusted `Authentication-Results`, alignment
   - `sender`: display-name and brand impersonation, look-alikes
   - `links`: via `tldts` and the Public Suffix List
   - `html`: inert parse with `htmlparser2`; nothing is rendered
   - `attachments`: type sniffing, `fflate` archive and OOXML inspection, PDF actions, QR in images
   - `content`: intents in several languages, urgency, obfuscation
   - `esp`: bulk-mailer and campaign IDs
3. **Findings and score** (`score.ts`):
   - Every finding has an id, a severity, a weight and human-readable evidence.
   - Weights are summed as logits, with per-category caps, trust credits (e.g. an aligned DMARC pass from a verified brand) and a floor for critical findings.
   - The result is a 0–100 risk score. Verdict thresholds come from the user's sensitivity setting.
4. **Fingerprint** (`fingerprint.ts`): the campaign features. These are MinHash (64 permutations, 16 LSH bands) and SimHash of the normalised text; the HTML skeleton hash; URL and path templates; Message-ID and header-order templates; ESP campaign IDs; attachment structure hashes; and a set of index keys.

## Campaign correlation

- **Candidates.** For each new message, `background/campaigns.ts` finds candidates through its index keys (LSH bands, templates, hashes) in IndexedDB.
- **Scoring.** `campaign/similarity.ts` scores each pair on seven weighted layers: content, URLs, attachments, infrastructure, sender, semantics and delivery. It also applies hard links, such as the same ESP campaign ID, the same attachment SHA-256, near-identical text or the same landing-page pattern.
- **Joining.** A message joins the best campaign at similarity ≥ 0.60. Campaigns merge at ≥ 0.72.
- **Profiling.** `profileCampaign` works out what the members share (invariants) and what varies (rotated attributes).

The design follows the *campaign, not IOC* principle: equality on indicators is replaced by similarity over layers attackers rarely change. The rotation experiment in `lab/` shows the effect.

## Threat feeds

`feeds/build_feeds.py` runs daily in GitHub Actions and publishes to the `feeds` branch. It:
1. downloads public lists
2. removes popular sites (Tranco)
3. compiles each list to a Bloom filter (murmur3 double hashing, p = 10⁻⁶)
4. publishes `v1/manifest.json` and `*.bloom` with SHA-256 digests

The add-on downloads the whole filters, verifies their digests, stores them in IndexedDB and tests hosts locally: each host and its parent domains, never siblings. No lookup ever leaves the device.

## UI

- **Stack.** Preact with a small design system (`extension/src/ui`): tokens for the dark *Abyss* and light *Reef* themes, Geist fonts, Lucide icons, and an animated SVG shark mark.
- **Isolation.** Everything injected into Gmail renders inside closed shadow roots, so Gmail's CSS cannot leak in and page scripts cannot read MailShark's DOM.
- **No HTML from strings.** No HTML is ever built from strings, and the build removes Preact's `innerHTML` code path.

## Tests

| Suite | What it covers |
|---|---|
| `engine/test` (vitest) | Unit tests; end-to-end verdicts on the `.eml` fixtures; campaign linking under rotation; detector regressions |
| `tests/e2e_firefox.py` | The built add-on loaded into real Gecko (Firefox or Zen) via Selenium and geckodriver against a Gmail mock. Covers the verdict banner, link guard, overlay layer, inbox radar, welcome page, Lab and campaign tracing. |
| `feeds/test_build_feeds.py` | Bit-exact Bloom compatibility with the TypeScript engine; allowlist rules |
| `lab/tests` | The Python forensic pipeline |
| `scripts/eval` | Accuracy on 16k real emails (see [ACCURACY.md](ACCURACY.md)) |
