# Limitations

What the platform does not do, does not claim, or does only partially. Read this before relying on a
result in a decision.

## Forensic standing

- **No claim of forensic soundness or of compliance with a standard.** The platform has not been
  evaluated against ISO/IEC 27037, 27041, 27042, NIST SP 800-86, ACPO principles or any accreditation
  scheme, and it does not claim conformity with any of them.
- **Hashing shows that the platform's copy is unchanged since intake, nothing more.** SHA-256 /
  SHA-1 / MD5 are computed while the upload streams in, stored with the record, and the bytes are
  re-verified on every read. This does not establish how the evidence was collected, whether it is
  complete, or whether it was altered before upload.
- **Uploads are the investigator's export.** A `.eml` saved from a mail client, an mbox from a
  takeout or a `.msg` from Outlook may already differ from what the mail server delivered (re-encoded
  headers, dropped trace headers, re-wrapped bodies). The platform records the derivation of every
  message (original, extracted from mbox/emlx, reconstructed from msg) but cannot recover what the
  export lost.
- **Outlook `.msg` is a reconstruction.** MAPI properties are turned back into an RFC 5322 message;
  header order, encodings and some headers can differ from the delivered message, and byte-level
  checks (DKIM body hash) are disabled for these messages.
- **The audit log is tamper-evident, not tamper-proof.** Entries are hash-chained and the database
  rejects updates and deletes through triggers, so modification of stored entries is detected by
  `audit-verify`. Someone with write access to the database file can rebuild the whole chain; export
  the chain head (`GET /api/admin/audit/verify`) to an independent system regularly if that matters.
- **Clock and time zone.** Times are recorded from the server clock (UTC). Message times come from
  the evidence (Date and Received headers), which senders can forge; timeline anomalies are reported
  as findings, not corrected.

## Detection

- **Measured on public corpora with known biases** (VALIDATION.md §2). The legitimate-mail corpus
  (SpamAssassin, 2002–2003) predates SPF, DKIM and DMARC, so the false-positive rate is not measured
  on modern authenticated mail, and authentication signals cannot be validated with it. The phishing
  corpora are honeypot and personal-inbox collections, not a sample of what reaches a given
  organisation.
- **Engine heuristics were developed with access to these corpora.** The content-hash holdout split
  protects the reported thresholds from being tuned on the holdout, not from design-time exposure.
- **About a quarter of the phishing in the corpora is classified benign** (recall of malicious +
  suspicious ≈ 75 %). Missed messages mostly carry no link, no attachment and no recognisable lure
  wording, or are authenticated messages from compromised or look-alike accounts. *Benign* means
  "nothing indicative was found in the available evidence", not "safe".
- **"Benign" precision depends on how much phishing is in the input.** On the corpus (74 % phishing)
  benign calls are often wrong; in a normal mailbox, where phishing is rare, they are mostly right.
  VALIDATION.md reports the rates conditioned on the true label and the derived precision at 1 % and
  10 % prevalence.
- **Confidence is a documented rule, not a calibrated probability.**
- **No attachment execution, no rendering, no link visits.** Attachments are parsed statically
  (structure, macros, embedded objects, archive listings, QR codes); obfuscated or encrypted payloads
  can hide behaviour that only dynamic analysis would show. Links are never fetched, so a landing page
  that is phishing today but looked harmless in the message is only detected through intelligence or
  the message itself.
- **DKIM header signatures** are verified only when the case allows online lookups (DNS), against the
  key published *now*; a rotated or revoked key makes an originally valid signature unverifiable.
  The offline body-hash check does not need the network.
- **Languages.** Lure, urgency and intent wording is detected from an English lexicon. For messages in
  other languages (the engine records the detected script/language), detection relies on sender,
  authentication, link, attachment and infrastructure signals only.

## Campaign correlation

- **Benchmarked on synthetic campaigns built from real phishing** (VALIDATION.md §3), because no
  public corpus labels phishing campaigns. Real campaigns can rotate more (content, structure,
  infrastructure) or less than the generator does. The benchmark labels are partial: pairs of
  confounders are not scored.
- **Clusters are local to a case** by design (case separation). The same indicator in another case
  the user can access is shown as a hint on the indicator page, never merged.
- **A cluster is not an attribution**, and an external association is a third-party report about an
  indicator. Generic indicator dumps are recognised by name and downgraded, but naming conventions
  vary by source; a generic record with a specific-sounding name would not be recognised.
- **Bulk-mail clusters**: legitimate newsletters from one sender form *bulk* clusters; this is
  expected and labelled, not an error.

## Intelligence

- **Not every integration was tested against the live service.** VirusTotal, PhishTank, the
  MalwareBazaar API and a MISP instance were tested only against mocked responses in the providers'
  documented formats, because no credentials or instance were available. The Tor exit list could not
  be fetched from the development network. See the table in CAMPAIGNS.md for exactly what ran live.
- **Feed freshness**: matches are as good as the latest synchronisation; the source page shows
  *stale* and *unavailable* sources, and every result records the snapshot it used.
- **Free feeds have limited coverage** of BEC, call-back and extortion mail, which often carries no
  URL or file.
- **Online lookups disclose the looked-up value** to the third party. They are off by default per
  case, explicit, rate-limited and audit-logged; the platform cannot control what the third party
  does with the query.

## Platform

- **Single node.** One server process with worker threads and SQLite (WAL). It is not clustered and
  has no built-in high availability; back up the data directory.
- **Authentication is local accounts only** (scrypt, server-side sessions, lockout after repeated
  failures). There is no SSO/OIDC, no MFA and no LDAP integration yet; put the platform behind a
  reverse proxy with SSO if that is required.
- **Retention is advisory.** A case can carry a retention date and is listed as overdue under
  Administration; deletion is never automatic. Legal hold blocks deletion. Deleted evidence is removed
  from the store unless another case references the same bytes; the deletion record (with hashes)
  stays in the audit log. Deletion does not securely wipe the underlying disk blocks.
- **Browsers.** The interface was exercised in a Chromium-based browser at desktop and phone widths
  (VALIDATION.md §5). An automated Firefox/Gecko end-to-end test exists
  (`tests/e2e_platform_firefox.py`) but has **not been run** in this environment, because no
  geckodriver was available for the installed Gecko browser. It needs JavaScript.
- **Mobile forensics** is not implemented. The data model (evidence → derived artifacts → findings,
  with derivation recorded) is generic, but only email formats are parsed.
