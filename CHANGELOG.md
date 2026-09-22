# Changelog

All notable changes to MailShark are documented here. Versions follow [Semantic Versioning](https://semver.org).

## 1.0.0: first public release

### Gmail integration
- Automatic dissection of every opened email, using Gmail's original message source (no OAuth, no downloads).
- Verdict banner (Safe / Suspicious / Dangerous) with the top reasons, and a compact mode for safe mail.
- Inspector drawer with eight panes: Verdict, Sender, Route, Links, Files, Content, Campaign and Source.
- Link guard that intercepts clicks on dangerous links.
- Inbox radar: verdict badges in the message list, with optional rate-limited scanning of unopened emails.
- Follows Gmail's light or dark theme.

### Engine
- Evidence-based scoring. Every finding has an explanation, a severity and a weight, and there are three sensitivity levels.
- Authentication (SPF, DKIM, DMARC, ARC) is read only from trusted receiving servers.
- Route forensics with the trusted hand-off hop.
- Sender checks: brand impersonation across about 200 brands, look-alike and homoglyph domains, Reply-To traps, recipient-organisation lures.
- Link checks: text/destination mismatch, redirects, shorteners, punycode, IP hosts, free hosting, executable downloads, QR codes in images.
- HTML checks: forms, scripts, hidden text, zero-width and invisible characters.
- Attachment checks: true type, double extensions, Office macros and remote templates, archives, PDF actions, HTML smuggling.
- Content checks: lures in several languages (credential, payment, gift card, crypto, MFA, delivery, tax, job, extortion, call-back, BEC), urgency, fake replies.
- Campaign fingerprints and local campaign correlation that survives rotated domains, senders, links and files.
- Public threat feeds (Phishing.Database, URLhaus) compiled to Bloom filters and checked locally.

### MailShark Lab
- Overview, Campaigns (interactive graph with invariants and rotated attributes), History, Analyze (`.eml` / `.mbox` import), Academy (10 lessons), Settings, About.
- Export as JSON, CSV (IOCs), Markdown and STIX 2.1.

### Privacy
- All analysis is on-device. No telemetry, analytics or accounts. Firefox data-collection disclosure: none.
