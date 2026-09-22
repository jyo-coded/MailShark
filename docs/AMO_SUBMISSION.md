# Publishing MailShark on addons.mozilla.org

Mozilla signs and hosts Firefox add-ons for free. Listed add-ons are available to everyone on Firefox, and on Gecko browsers such as Zen, Floorp and LibreWolf.

## 1. Build the release

From a clean, committed tree:

```bash
npm ci
npm run verify      # typecheck, tests, build, addons-linter
npm run package     # artifacts/mailshark-1.0.0.zip  +  artifacts/mailshark-1.0.0-source.zip
```

`npm run package` refuses to run with uncommitted changes to shipped files. It fails if addons-linter reports any error, warning or notice.

## 2. Submit

1. Sign in at https://addons.mozilla.org/developers/ with a Firefox account. Enable two-factor authentication; AMO requires it for submission.
2. **Submit a New Add-on → On this site** (listed).
3. Upload `artifacts/mailshark-1.0.0.zip`.
   - **Compatible platforms:** tick **Firefox** only. Leave **Firefox for Android** unticked, because Gmail's mobile site uses a different page layout that MailShark does not support yet.
4. **Source code:** answer **Yes**, the add-on uses a build tool. Upload `artifacts/mailshark-1.0.0-source.zip`. It contains [BUILDING.md](BUILDING.md) with the exact steps.
5. Fill in the listing (section 3) and paste the reviewer notes (section 4).
6. Submit. Automated validation runs immediately, and the add-on is usually live within minutes to hours. Human review may happen afterwards; answer reviewer messages from the Developer Hub.

For later versions:
1. Bump `version` in `package.json` and update `CHANGELOG.md`.
2. Commit, run `npm run package`, then **Upload New Version**.

The add-on id (`mailshark@jyo-coded.github.io`) never changes.

## 3. Listing

| Field | Value |
|---|---|
| **Name** | MailShark: Phishing Forensics for Gmail |
| **Add-on URL** | `mailshark` |
| **Summary** (≤ 250 chars) | Dissects every Gmail message on your device: sender forensics, link and attachment analysis, and tracing of phishing campaigns across your inbox. Clear verdicts, with every reason explained. No servers, no tracking. |
| **Categories** | Privacy & Security |
| **Tags** | phishing, security, gmail, email, forensics, privacy |
| **Support site** | https://github.com/jyo-coded/MailShark/issues |
| **Homepage** | https://github.com/jyo-coded/MailShark |
| **License** | MIT License |
| **Privacy policy** | Paste the contents of [PRIVACY.md](../PRIVACY.md) |
| **Requires payment / non-free** | No |
| **Experimental** | No |

**Description:**

```
MailShark checks every email you open in Gmail, the way a forensic analyst would, and tells you in plain language whether it is safe.

WHAT IT DOES
• A verdict banner on every email: Safe, Suspicious or Dangerous, with the reasons.
• An inspector with eight panes: sender, delivery route, authentication (SPF, DKIM, DMARC), real link destinations, attachments, content and the raw source.
• Link guard: clicking a dangerous link shows you where it really leads before anything opens.
• Inbox radar: warning badges in your inbox list, even before you open an email.
• Campaign tracing: attackers rotate domains, senders and files between waves. MailShark links the variants into one campaign and shows what stayed constant.
• Lab: history, campaign graph, offline analysis of .eml and .mbox files, exports (JSON, CSV, Markdown, STIX 2.1) and short lessons on phishing tactics.

WHAT IT CHECKS
Brand impersonation, look-alike and homoglyph domains, Reply-To traps, failed or forged authentication, deceptive links, redirects and shorteners, QR codes in images, credential forms, hidden text, Office macros, dangerous archives, HTML smuggling, PDF actions, and credential, payment, gift-card, crypto, MFA and call-back lures in several languages.

PRIVATE BY DESIGN
Every email is analysed inside your browser. MailShark has no server, no account, no analytics and no telemetry, and it never sends your email anywhere. Optional public threat lists are downloaded and checked locally.

ACCURACY
Tested on 16,228 real emails from public research corpora: 85.7% of the Nazario phishing corpus flagged, 0.26% of unseen legitimate mail flagged. Methodology: https://github.com/jyo-coded/MailShark/blob/main/docs/ACCURACY.md

Open source (MIT): https://github.com/jyo-coded/MailShark
```

**Screenshots** (1280 × 800 PNG, captured in real Gecko by `tests/e2e_firefox.py --size 1280x800`) are in [`docs/screenshots/`](screenshots/). Upload them in file-name order:

| File | Caption |
|---|---|
| `1-banner.png` | Every email gets a verdict, with the reasons, right above the message. |
| `2-inspector.png` | The Dissector: sender, route, authentication, links, files, content and source. |
| `3-link-guard.png` | Link guard shows where a deceptive link really leads before it opens. |
| `4-campaign.png` | Campaign tracing: what the attacker rotated, and what gave them away. |
| `5-lab-overview.png` | The Lab: threats caught, campaigns and impersonated brands. |
| `6-inbox-radar.png` | Inbox radar: verdict badges before you even open an email. |
| `7-analyze.png` | Offline forensics for saved .eml and .mbox files. |
| `8-academy.png` | Short lessons on the tactics MailShark detects. |

These screenshots use the Gmail mock from the test harness. For a more convincing listing, retake shots 1–3 and 6 in your own Gmail with real (or sample) phishing mail at a 1280 × 800 window.

## 4. Notes to reviewer

```
Thank you for reviewing MailShark.

BUILD
The bundles are produced by esbuild from TypeScript and are NOT minified (identifiers and formatting are preserved).
Rebuild with Node 22 and npm 10:
  npm ci
  npm run build
Output: dist/firefox/, identical to the submitted package. Details are in docs/BUILDING.md inside the source archive.

HOW IT WORKS
• The content script runs only on https://mail.google.com/*. When the user opens an email, it reads the message's legacy id from the page (div[data-legacy-message-id]). It then fetches Gmail's own "Show original" data from the same origin (?view=att&th=<id>&attid=0&disp=comp&safe=1&zw) with the user's session.
• The raw message is sent to the background page and analysed there by pure TypeScript (engine/src). No email data leaves the browser.
• Everything injected into Gmail renders inside closed shadow roots, using Preact. No HTML is built from strings: the build replaces Preact's innerHTML code path (scripts/build-lib.mjs), and the bundles contain no innerHTML assignments, eval or Function().
• The only other network request downloads public threat-list DATA (Bloom filters, not code) every 12 hours, from https://raw.githubusercontent.com/jyo-coded/MailShark/feeds/v1/. It is sent with credentials omitted, integrity-checked with SHA-256, and can be disabled in Settings. No remote code is loaded.
• data_collection_permissions: none. No telemetry or analytics.

TESTING WITHOUT A GMAIL ACCOUNT
Open the add-on's Lab (toolbar icon → "Open MailShark Lab" → "Analyze files") and drop the sample emails from fixtures/eml/ in the source archive. They are synthetic, harmless phishing examples: look-alike PayPal, QR-code phishing, a macro invoice, a SharePoint campaign in 4 rotated variants, and legitimate mail.
The results appear in History and Campaigns exactly as they would for Gmail messages.

With Gmail: install the add-on, open https://mail.google.com and open any email. A MailShark banner appears above the message body. Click "Dissect" for the full analysis.

PERMISSIONS
• mail.google.com: overlay UI and fetching the source of the opened message
• storage + unlimitedStorage: local evidence database (reports, campaigns)
• alarms: periodic threat-feed refresh
```

## 5. After publishing

- **Feeds.** Enable the daily feed workflow (see `.github/workflows/feeds.yml`) before or right after release. Until the first run creates the `feeds` branch, Settings → Public threat feeds shows "last attempt: Feed manifest unavailable (HTTP 404)", and the add-on works without intel.
- **Gmail changes.** Watch GitHub issues for Gmail layout changes. All Gmail-specific selectors are in `extension/src/content/gmail.ts`.
