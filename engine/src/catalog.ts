// Finding catalogue: for every finding id, how it is established, why it matters, what limits its
// reliability, what an investigator should do next, and the MITRE ATT&CK technique it maps to.
// Reports attach this to each finding so that conclusions are reviewable without reading code.
import type { DetectionMethod } from './types';

export interface FindingDoc {
  method: DetectionMethod;
  /** Why the observation matters (beyond the finding's own detail text). */
  rationale: string;
  limitations: string;
  actions: string[];
  attack?: { id: string; name: string }[];
}

const T = {
  phishing: { id: 'T1566', name: 'Phishing' },
  link: { id: 'T1566.002', name: 'Phishing: Spearphishing Link' },
  attachment: { id: 'T1566.001', name: 'Phishing: Spearphishing Attachment' },
  voice: { id: 'T1566.004', name: 'Phishing: Spearphishing Voice' },
  infoLink: { id: 'T1598.003', name: 'Phishing for Information: Spearphishing Link' },
  impersonation: { id: 'T1656', name: 'Impersonation' },
  masquerading: { id: 'T1036', name: 'Masquerading' },
  doubleExt: { id: 'T1036.007', name: 'Masquerading: Double File Extension' },
  rtlo: { id: 'T1036.002', name: 'Masquerading: Right-to-Left Override' },
  obfuscation: { id: 'T1027', name: 'Obfuscated Files or Information' },
  smuggling: { id: 'T1027.006', name: 'Obfuscated Files or Information: HTML Smuggling' },
  userLink: { id: 'T1204.001', name: 'User Execution: Malicious Link' },
  userFile: { id: 'T1204.002', name: 'User Execution: Malicious File' },
  domains: { id: 'T1583.001', name: 'Acquire Infrastructure: Domains' },
  compromisedEmail: { id: 'T1586.002', name: 'Compromise Accounts: Email Accounts' },
  compromisedServer: { id: 'T1584.004', name: 'Compromise Infrastructure: Server' },
  templateInjection: { id: 'T1221', name: 'Template Injection' },
  vba: { id: 'T1059.005', name: 'Command and Scripting Interpreter: Visual Basic' },
  dde: { id: 'T1559.002', name: 'Inter-Process Communication: Dynamic Data Exchange' },
  linkTarget: { id: 'T1608.005', name: 'Stage Capabilities: Link Target' },
} as const;

const A = {
  scope: 'Search the mail gateway / mailbox logs for other recipients of the same sender, subject template and links to scope the campaign.',
  proxy: 'Check proxy, DNS and EDR telemetry for visits to the linked hosts by any recipient.',
  hash: 'Look up the attachment hashes in malware repositories and, if permitted, detonate the file in an isolated sandbox.',
  original: 'Obtain the original message from the server or journal (not a forwarded copy) to confirm the headers.',
  abuse: 'Report the infrastructure to the hosting provider or registrar abuse desk and preserve the evidence first.',
  replies: 'Check whether any recipient replied, clicked or called; interview them if so.',
  creds: 'If a recipient entered credentials, reset them, revoke sessions and review sign-in logs.',
  dmarc: "Review the sender domain's DMARC policy and aggregate reports if you control it.",
};

const DOCS: Record<string, FindingDoc> = {
  // ── Sender identity ──
  'sender.brand-impersonation': {
    method: 'heuristic',
    rationale: 'Display names are free text: claiming a brand while sending from an unrelated domain is the core move of brand phishing.',
    limitations: 'The brand registry covers about 200 frequently impersonated brands. Resellers and agencies legitimately use brand names; check the authentication results and the context.',
    actions: [A.scope, A.proxy, A.creds],
    attack: [T.impersonation, T.phishing],
  },
  'sender.lookalike-domain': {
    method: 'heuristic',
    rationale: 'The sender domain differs from a real brand domain by homoglyphs or one or two edits. Such domains are registered to deceive.',
    limitations: 'Short labels and dictionary words can collide by chance; the registration date (WHOIS/RDAP) is not checked offline.',
    actions: ['Check the domain registration date and registrant via RDAP.', A.abuse, A.scope],
    attack: [T.domains, T.impersonation],
  },
  'sender.brand-in-domain': {
    method: 'heuristic',
    rationale: 'A brand name embedded in an unrelated sender domain is a common lure. Partners and resellers sometimes do this legitimately.',
    limitations: 'Weak on its own; many legitimate businesses contain brand-like words.',
    actions: ['Check whether the domain is an authorised partner of the brand.'],
    attack: [T.domains],
  },
  'sender.recipient-org-lure': {
    method: 'heuristic',
    rationale: 'Messages that invoke the recipient’s own organisation from an outside domain imitate internal IT or HR to harvest credentials.',
    limitations: 'Depends on identifying the recipient (Delivered-To / To). Shared services named after the organisation can trigger it.',
    actions: [A.scope, A.creds],
    attack: [T.impersonation, T.infoLink],
  },
  'sender.role-name': {
    method: 'heuristic',
    rationale: 'Generic IT or mail-system role names ("Mail Administrator") are a classic disguise for mailbox and password lures.',
    limitations: 'Real help desks use such names from their own domain; the finding only fires for outside senders.',
    actions: [A.scope],
    attack: [T.impersonation],
  },
  'sender.invisible-chars': {
    method: 'heuristic',
    rationale: 'Zero-width and tag characters split brand names and keywords so that filters cannot read them, while the text looks normal to people.',
    limitations: 'Rarely legitimate in names and subjects; some emoji sequences use joiners.',
    actions: [A.scope],
    attack: [T.obfuscation],
  },
  'content.styled-letters': {
    method: 'heuristic',
    rationale: 'Mathematical Unicode letters evade keyword filters.',
    limitations: 'Also used by legitimate marketing for emphasis.',
    actions: [],
    attack: [T.obfuscation],
  },
  'sender.no-address': {
    method: 'protocol',
    rationale: 'RFC 5322 requires a From mailbox. A missing address points to hand-crafted or malformed mail.',
    limitations: 'Some malformed legitimate automated mail exists.',
    actions: [A.original],
  },
  'sender.display-name-address': {
    method: 'heuristic',
    rationale: 'Putting a trusted address in the display name hides the real sender in clients that show only names.',
    limitations: 'Some mailing systems repeat the address in the name.',
    actions: [A.scope],
    attack: [T.impersonation],
  },
  'sender.homoglyph-name': {
    method: 'heuristic',
    rationale: 'Mixed-script display names imitate brands while evading exact-match filters.',
    limitations: 'Bilingual names can mix scripts legitimately.',
    actions: [A.scope],
    attack: [T.impersonation, T.obfuscation],
  },
  'sender.reply-to-freemail': {
    method: 'heuristic',
    rationale: 'Replies diverted to a free webmail account are the signature of business email compromise and advance-fee fraud.',
    limitations: 'Small businesses sometimes do use personal webmail for replies.',
    actions: [A.replies, 'Preserve the Reply-To mailbox as an indicator; request subscriber data from the provider through legal process.'],
    attack: [T.impersonation],
  },
  'sender.reply-to-mismatch': {
    method: 'heuristic',
    rationale: 'Replies go to a different organisation than the visible sender.',
    limitations: 'Common with ticketing systems, ESPs and mailing lists, so the weight is low.',
    actions: [A.replies],
  },
  'sender.freemail-business': {
    method: 'heuristic',
    rationale: 'Payment, gift-card and job requests from personal webmail accounts are typical of fraud.',
    limitations: 'Contextual; legitimate individuals use webmail.',
    actions: [A.replies],
  },
  'sender.verified-brand': {
    method: 'protocol',
    rationale: 'The message is authenticated (DMARC alignment, an aligned DKIM signature, or a signature verified offline) for a domain the brand owns.',
    limitations: 'Authentication proves the domain, not intent. Compromised brand accounts and abused brand services (e.g. invoicing tools) still pass.',
    actions: [],
  },
  'sender.known': {
    method: 'correlation',
    rationale: 'The address has written to this mailbox repeatedly before.',
    limitations: 'Previously seen senders can be compromised.',
    actions: [],
  },
  'sender.first-time': {
    method: 'correlation',
    rationale: 'First contact from this address.',
    limitations: 'Very weak on its own.',
    actions: [],
  },

  // ── Authentication ──
  'auth.none': {
    method: 'protocol',
    rationale: 'This copy carries no receiver verdicts, so SPF, DKIM and DMARC cannot be assessed from the receiving server’s view.',
    limitations: 'Absence is not a failure. Exported or forwarded copies often lose these headers.',
    actions: [A.original],
  },
  'auth.unverified-results': {
    method: 'protocol',
    rationale: 'Authentication-Results headers are present but could not be attributed to the receiving organisation. A sender can insert such headers, so their verdicts are not relied on.',
    limitations: 'Happens legitimately with unusual relay chains and with exports that drop the receiver’s headers.',
    actions: [A.original],
  },
  'auth.injected-results': {
    method: 'protocol',
    rationale: 'A verdict header was already in the message before the receiver accepted it, or it names a provider that never handled the message. Attackers insert fake "pass" results to mislead filters and analysts.',
    limitations: 'Complex forwarding chains can carry a legitimate earlier hop’s verdicts; check the Received path.',
    actions: [A.original, A.scope],
    attack: [T.masquerading],
  },
  'auth.dmarc-fail': {
    method: 'protocol',
    rationale: 'The From domain publishes DMARC and the message failed it: the visible sender domain was not authorised to send this message.',
    limitations: 'Forwarding and mailing lists can break DMARC for legitimate mail (ARC may record the original result).',
    actions: [A.dmarc, A.scope],
    attack: [T.impersonation],
  },
  'auth.compauth-fail': {
    method: 'protocol',
    rationale: 'Microsoft’s composite authentication could not establish the sender.',
    limitations: 'A proprietary verdict; implicit authentication can differ from DMARC.',
    actions: [A.scope],
  },
  'auth.spf-fail': {
    method: 'protocol',
    rationale: 'The sending server is not authorised by the envelope domain’s SPF record, and no valid DKIM signature compensates.',
    limitations: 'SPF breaks on forwarding. Covers the envelope sender, not necessarily the visible From.',
    actions: [A.scope],
  },
  'auth.dkim-fail': {
    method: 'protocol',
    rationale: 'A DKIM signature did not verify at the receiver: the message was altered or the signature forged.',
    limitations: 'Mailing lists and gateways that modify messages break signatures legitimately.',
    actions: [A.original],
  },
  'auth.dmarc-pass': {
    method: 'protocol',
    rationale: 'The receiver verified that the From domain authorised this message.',
    limitations: 'Proves domain authorisation only. Attackers register their own domains and pass DMARC easily.',
    actions: [],
  },
  'auth.unaligned': {
    method: 'protocol',
    rationale: 'SPF/DKIM passed for a different domain than the visible From, so the From address itself is unverified.',
    limitations: 'Common for ESP-sent mail without custom DKIM.',
    actions: [],
  },

  // ── DKIM (offline / key-verified) ──
  'dkim.signature-verified': {
    method: 'protocol',
    rationale: 'The DKIM signature verifies against the key currently published by the signing domain, and the body hash matches: the signed headers and body are as the domain signed them.',
    limitations: 'Proves the signing domain only. Verification uses today’s key; a domain could have re-used a selector.',
    actions: [],
  },
  'dkim.signature-invalid': {
    method: 'protocol',
    rationale: 'The signature does not verify against the published key: the signed headers were altered after signing, or the signature was forged.',
    limitations: 'Key rotation under the same selector produces the same result for genuine old mail.',
    actions: [A.original],
  },
  'dkim.body-modified': {
    method: 'protocol',
    rationale: 'The body differs from what the signing domain hashed. It changed after signing: list footers, gateway link rewriting, mailbox processing, or tampering.',
    limitations: 'Usually benign (gateways and lists modify bodies). It matters for the integrity of the evidence copy.',
    actions: [A.original],
  },
  'dkim.modified-after-delivery': {
    method: 'protocol',
    rationale: 'The receiving server recorded a valid DKIM signature at delivery, but the body in this evidence copy no longer matches it. The copy was changed after delivery (e.g. Safe Links rewriting, a mailbox rule, an export tool, or tampering).',
    limitations: 'Cannot tell benign post-delivery processing from manual tampering. Compare with a server-side copy.',
    actions: ['Treat this copy as modified evidence; obtain the message from the server, journal or a provider export.', A.original],
  },
  'dkim.body-appended': {
    method: 'protocol',
    rationale: 'The signature covers only the first l= octets of the body and the evidence contains more. Content was appended after signing, a known way to abuse legitimately signed messages.',
    limitations: 'Some lists append footers to l=-signed mail; the appended part must be reviewed.',
    actions: ['Review the appended content separately; it is not covered by the signature.', A.scope],
    attack: [T.masquerading],
  },
  'dkim.replay-suspected': {
    method: 'protocol',
    rationale: 'A valid signature created long before delivery (and/or not naming this recipient) suggests DKIM replay: a genuinely signed message re-sent to new victims to borrow the signer’s reputation.',
    limitations: 'Delayed delivery and Bcc legitimately produce similar patterns.',
    actions: [A.scope, 'Report the replay to the signing domain owner.'],
    attack: [T.impersonation],
  },
  'dkim.from-unsigned': {
    method: 'protocol',
    rationale: 'RFC 6376 requires From in the signed header list; a signature that does not cover From does not vouch for the visible sender.',
    limitations: 'Such signatures are invalid per the RFC and ignored by most verifiers.',
    actions: [],
  },
  'dkim.weak-crypto': {
    method: 'protocol',
    rationale: 'RSA keys shorter than 1024 bits or SHA-1 are deprecated (RFC 8301); such signatures can be forged.',
    limitations: 'Many legacy senders still use them.',
    actions: [],
  },

  // ── Route / infrastructure ──
  'route.origin': {
    method: 'protocol',
    rationale: 'The connecting server as recorded by the receiving organisation: the last verifiable point on the delivery path.',
    limitations: 'Hops below the hand-off were written by the sender side and may be forged. Shared ESP and provider IPs serve many customers.',
    actions: ['Check the origin IP’s ASN and abuse contact; correlate with other messages from the same network.'],
  },
  'route.date-skew': {
    method: 'heuristic',
    rationale: 'The Date header disagrees with the receiver’s timestamp: scripted senders and re-sent old messages show this.',
    limitations: 'Delayed queues and wrong client clocks.',
    actions: [],
  },
  'route.esp': {
    method: 'heuristic',
    rationale: 'Bulk-mail infrastructure and its campaign/customer identifiers: strong campaign keys.',
    limitations: 'ESPs carry legitimate and malicious customers alike.',
    actions: ['Report abusive campaigns to the ESP with the campaign/customer IDs.'],
  },
  'route.mass-mailer': {
    method: 'heuristic',
    rationale: 'Mass-mailing scripts are typical of spam kits and compromised web servers.',
    limitations: 'Also used by small legitimate websites.',
    actions: [A.abuse],
    attack: [T.compromisedServer],
  },
  'route.helo-impersonation': {
    method: 'protocol',
    rationale: 'The connecting server introduced itself (HELO/EHLO) with a brand or provider name that its reverse DNS does not support.',
    limitations: 'HELO is unauthenticated; misconfigured servers exist. Only the hand-off hop is evaluated.',
    actions: ['Record the origin IP and HELO name as infrastructure indicators.'],
    attack: [T.masquerading],
  },
  'route.authenticated-sender-mismatch': {
    method: 'heuristic',
    rationale: 'The provider recorded that a mailbox of another domain authenticated to send this message: typical of a compromised hosting account sending spoofed mail.',
    limitations: 'Provider trace headers are written by the sending side and cannot be verified by the recipient.',
    actions: [A.abuse, 'Ask the hosting provider (see X-AntiAbuse / authenticated id) to secure the account.'],
    attack: [T.compromisedEmail],
  },
  'route.script-sender': {
    method: 'heuristic',
    rationale: 'A web script generated the message: the path usually identifies a compromised or malicious website on shared hosting.',
    limitations: 'Contact forms and shops send legitimate mail this way too.',
    actions: [A.abuse],
    attack: [T.compromisedServer],
  },
  'route.originating-client': {
    method: 'heuristic',
    rationale: 'The sending provider recorded the IP address of the client that composed the message. It can attribute the sending session.',
    limitations: 'Written by the sending provider, not verifiable by the recipient; may be a VPN, proxy or carrier NAT address.',
    actions: ['Preserve the client IP; request session logs from the provider through legal process.'],
  },
  'route.timestamp-anomaly': {
    method: 'heuristic',
    rationale: 'Received timestamps go backwards in time: forged trace headers or misconfigured clocks.',
    limitations: 'Clock drift on relays; only large inversions are reported.',
    actions: [],
  },
  'route.mailing-list': {
    method: 'heuristic',
    rationale: 'Discussion-list headers explain rewritten Reply-To and loose threading.',
    limitations: 'Attackers can add list headers; trust credit is small.',
    actions: [],
  },

  // ── Links ──
  'links.threat-intel': {
    method: 'intel',
    rationale: 'A linked host or URL is listed on a public threat-intelligence feed.',
    limitations: 'Feeds contain errors and compromised legitimate sites; listing dates matter (see the intelligence section).',
    actions: [A.proxy, A.creds],
    attack: [T.link, T.userLink],
  },
  'links.lookalike': {
    method: 'heuristic',
    rationale: 'A link targets a domain that imitates a brand domain.',
    limitations: 'Brand registry coverage; homoglyph detection uses a confusables subset.',
    actions: [A.proxy, A.abuse],
    attack: [T.link, T.domains],
  },
  'links.brand-embedded': {
    method: 'heuristic',
    rationale: 'A brand name used as a decoy label inside another domain.',
    limitations: 'Affiliate and partner domains.',
    actions: [A.proxy],
    attack: [T.link],
  },
  'links.text-mismatch': {
    method: 'heuristic',
    rationale: 'The visible link text names one site while the link opens another.',
    limitations: 'Newsletter click-trackers rewrite links legitimately; recognised trackers are excluded.',
    actions: [A.proxy],
    attack: [T.link, T.masquerading],
  },
  'links.ip-host': {
    method: 'heuristic',
    rationale: 'Links to bare IP addresses avoid domain reputation systems.',
    limitations: 'Some internal or device links use IPs.',
    actions: [A.proxy],
    attack: [T.link],
  },
  'links.punycode': {
    method: 'heuristic',
    rationale: 'Internationalised domains can render as familiar Latin names.',
    limitations: 'Legitimate IDNs exist in many languages.',
    actions: [A.proxy],
    attack: [T.link, T.domains],
  },
  'links.script-uri': {
    method: 'heuristic',
    rationale: 'javascript:, data: and similar URIs execute content instead of navigating.',
    limitations: 'Nearly never legitimate in mail.',
    actions: [],
    attack: [T.userLink],
  },
  'links.credentials-in-url': {
    method: 'heuristic',
    rationale: 'Text before "@" in a URL is ignored by browsers: a disguise trick.',
    limitations: 'Rare legitimate authenticated URLs.',
    actions: [A.proxy],
    attack: [T.link, T.masquerading],
  },
  'links.ipfs': {
    method: 'heuristic',
    rationale: 'IPFS gateways host phishing kits that are hard to take down.',
    limitations: 'Legitimate decentralised content exists.',
    actions: [A.proxy],
    attack: [T.linkTarget],
  },
  'links.free-hosting': {
    method: 'heuristic',
    rationale: 'Free site builders, forms and object storage are heavily abused for credential pages.',
    limitations: 'Widely used legitimately; weight depends on the lure context.',
    actions: [A.proxy, A.abuse],
    attack: [T.linkTarget],
  },
  'links.file-download': {
    method: 'heuristic',
    rationale: 'The link points directly at an executable, script, disk image or macro document.',
    limitations: 'Software vendors link installers.',
    actions: [A.proxy, A.hash],
    attack: [T.userFile, T.link],
  },
  'links.archive-download': {
    method: 'heuristic',
    rationale: 'Archives hide payloads from scanners.',
    limitations: 'Common for legitimate file sharing.',
    actions: [A.proxy],
  },
  'links.nonstandard-port': {
    method: 'heuristic',
    rationale: 'Web links rarely specify ports; phishing kits on compromised hosts often do.',
    limitations: 'Development servers and appliances.',
    actions: [A.proxy],
  },
  'links.shortener': {
    method: 'heuristic',
    rationale: 'Shorteners conceal the destination.',
    limitations: 'Widely used legitimately.',
    actions: [],
  },
  'links.suspicious-tld': {
    method: 'statistical',
    rationale: 'TLDs with persistently high abuse rates in industry reports.',
    limitations: 'A population statistic, not evidence about this domain.',
    actions: [],
  },
  'links.redirect': {
    method: 'heuristic',
    rationale: 'Open redirects bounce victims through trusted domains.',
    limitations: 'Many legitimate trackers redirect.',
    actions: [A.proxy],
  },

  // ── Content ──
  'content.brand-lure': {
    method: 'heuristic',
    rationale: 'The text uses a brand’s name for an account or order lure, while the sender and links belong elsewhere.',
    limitations: 'Lexicon-based intent detection; third-party notices about a brand can match.',
    actions: [A.scope, A.proxy],
    attack: [T.impersonation, T.infoLink],
  },
  'content.intent': {
    method: 'heuristic',
    rationale: 'Wording matches a known lure playbook (credential, payment, delivery, document, tax, job, reward, extortion, call-back or BEC). Every matched phrase is reported.',
    limitations: 'Phrase lexicons in several languages; legitimate notifications use similar wording, so intent alone carries limited weight.',
    actions: [A.scope],
    attack: [T.phishing],
  },
  'content.homoglyph-subject': {
    method: 'heuristic',
    rationale: 'Letters from other alphabets disguise keywords in the subject.',
    limitations: 'Multilingual subjects.',
    actions: [],
    attack: [T.obfuscation],
  },
  'content.personalized-subject': {
    method: 'heuristic',
    rationale: 'Mass lures paste the recipient address into the subject to look personal.',
    limitations: 'Some legitimate services include usernames.',
    actions: [],
  },
  'content.callback-phone': {
    method: 'heuristic',
    rationale: 'Call-back (TOAD) scams move the victim to a phone call, beyond email security controls.',
    limitations: 'Legitimate invoices contain support numbers.',
    actions: ['Record the phone number as an indicator; report it to the carrier / national fraud reporting service.', A.replies],
    attack: [T.voice],
  },
  'content.split-words': {
    method: 'heuristic',
    rationale: 'Words broken with spaces defeat keyword filters.',
    limitations: 'Languages with short words; scoring uses a fragment ratio.',
    actions: [],
    attack: [T.obfuscation],
  },
  'content.urgency': {
    method: 'heuristic',
    rationale: 'Deadlines and threats push victims to act without checking.',
    limitations: 'Legitimate deadlines exist.',
    actions: [],
  },
  'content.generic-greeting': {
    method: 'heuristic',
    rationale: 'Mass lures do not know the recipient’s name.',
    limitations: 'Very weak.',
    actions: [],
  },
  'content.fake-reply': {
    method: 'protocol',
    rationale: 'A "Re:"/"Fwd:" subject without In-Reply-To/References fakes an existing conversation.',
    limitations: 'Some clients drop threading headers.',
    actions: [],
  },
  'content.enable-content': {
    method: 'heuristic',
    rationale: 'Instructions to enable editing or macros are how document malware activates.',
    limitations: 'Legitimate macro documents exist in some workflows.',
    actions: [A.hash],
    attack: [T.userFile, T.vba],
  },
  'content.password-archive': {
    method: 'heuristic',
    rationale: 'An encrypted attachment with its password in the body defeats gateway scanning.',
    limitations: 'Some organisations share sensitive files this way legitimately.',
    actions: ['Decrypt the archive in an isolated environment using the password from the body.', A.hash],
    attack: [T.obfuscation, T.userFile],
  },
  'content.crypto-wallet': {
    method: 'heuristic',
    rationale: 'Cryptocurrency addresses in extortion or payment lures identify where victims are told to pay.',
    limitations: 'Legitimate donation and payment requests contain addresses too.',
    actions: ['Trace the wallet on a blockchain explorer; report it to the exchange or law-enforcement channel.'],
  },

  // ── HTML ──
  'html.credential-form': {
    method: 'heuristic',
    rationale: 'A password field inside the email collects credentials directly.',
    limitations: 'Essentially never legitimate.',
    actions: [A.creds, A.proxy],
    attack: [T.infoLink],
  },
  'html.form': {
    method: 'heuristic',
    rationale: 'Embedded forms submit data to third parties.',
    limitations: 'Surveys and newsletters.',
    actions: [],
  },
  'html.script': {
    method: 'heuristic',
    rationale: 'Mail clients block scripts; their presence indicates hand-crafted or malicious HTML.',
    limitations: 'Some templating tools leave scripts in.',
    actions: [],
  },
  'html.iframe': { method: 'heuristic', rationale: 'Frames embed remote content.', limitations: 'Rare legitimate use.', actions: [] },
  'html.meta-refresh': { method: 'heuristic', rationale: 'Automatic redirection.', limitations: 'Rare in mail.', actions: [A.proxy] },
  'html.hidden-text': {
    method: 'heuristic',
    rationale: 'Invisible filler text manipulates content filters ("hidden text salting").',
    limitations: 'Preheader text in newsletters is often hidden; thresholds account for it.',
    actions: [],
    attack: [T.obfuscation],
  },
  'html.zero-width': { method: 'heuristic', rationale: 'Zero-width characters break up words for filters.', limitations: 'Some templates.', actions: [], attack: [T.obfuscation] },
  'html.image-only': { method: 'heuristic', rationale: 'Text rendered as an image hides wording from filters.', limitations: 'Image newsletters.', actions: [] },
  'html.image-with-filler': { method: 'heuristic', rationale: 'Combined image-only body and hidden filler text.', limitations: 'Rare legitimately.', actions: [], attack: [T.obfuscation] },
  'html.tracking': { method: 'heuristic', rationale: 'Read-tracking pixel.', limitations: 'Ubiquitous in marketing.', actions: [] },

  // ── Attachments ──
  'attachments.executable': {
    method: 'heuristic',
    rationale: 'Executables, disk images and disguised extensions run code when opened.',
    limitations: 'Type determined by magic bytes and extension; contents are not executed.',
    actions: [A.hash, A.scope, 'Isolate any host where the file was opened.'],
    attack: [T.attachment, T.userFile, T.doubleExt, T.rtlo],
  },
  'attachments.html-phish': {
    method: 'heuristic',
    rationale: 'HTML/SVG attachments with credential forms or blob-assembly code (HTML smuggling) bypass link scanning.',
    limitations: 'Static inspection; heavily obfuscated scripts may hide their purpose.',
    actions: [A.hash, A.creds],
    attack: [T.attachment, T.smuggling],
  },
  'attachments.active-content': {
    method: 'heuristic',
    rationale: 'Macros, remote templates, DDE fields and auto-run PDF scripts are document-malware mechanisms.',
    limitations: 'Static flags; benign macro documents exist.',
    actions: [A.hash],
    attack: [T.attachment, T.vba, T.templateInjection, T.dde],
  },
  'attachments.risky': {
    method: 'heuristic',
    rationale: 'Attachment types and traits that are frequently weaponised (macro formats, OneNote, type mismatch, encrypted archives, HTML).',
    limitations: 'Each trait has legitimate uses.',
    actions: [A.hash],
    attack: [T.attachment],
  },
  'attachments.qr': {
    method: 'heuristic',
    rationale: 'QR codes move the victim to a phone, outside corporate controls ("quishing").',
    limitations: 'Decoding depends on image quality.',
    actions: [A.proxy, A.creds],
    attack: [T.link],
  },
  'attachments.note': { method: 'heuristic', rationale: 'Attachment traits worth review.', limitations: 'Low signal.', actions: [] },

  // ── Structure ──
  'structure.duplicate-headers': {
    method: 'protocol',
    rationale: 'Duplicate single-instance headers (RFC 5322 §3.6) cause clients and filters to disagree about the sender or subject.',
    limitations: 'Some broken legitimate software duplicates headers.',
    actions: [A.original],
    attack: [T.masquerading],
  },
  'structure.anomalies': { method: 'protocol', rationale: 'MIME structure violations produced by hand-made or evasive mail.', limitations: 'Broken legitimate mailers.', actions: [] },
  'structure.divergence': {
    method: 'heuristic',
    rationale: 'Text and HTML alternatives say different things: filters read one, people see the other.',
    limitations: 'Some templates have generic text parts.',
    actions: [],
    attack: [T.obfuscation],
  },

  // ── Intelligence & correlation (platform) ──
  'intel.sender-domain': {
    method: 'intel',
    rationale: 'The sender domain is listed on a threat feed.',
    limitations: 'Feeds list compromised legitimate domains; see source and dates.',
    actions: [A.scope],
  },
  'intel.match': {
    method: 'intel',
    rationale: 'An indicator from this message is listed by an external intelligence source (exact match after normalisation).',
    limitations: 'A listing reflects the source’s observation at its time; absence from feeds does not imply safety.',
    actions: [A.scope, A.proxy],
  },
  'intel.campaign': {
    method: 'intel',
    rationale: 'Indicators from this message appear in an externally documented event or campaign.',
    limitations: 'Association is inferred from shared indicators; the external record’s own reliability applies.',
    actions: ['Read the referenced report; compare the documented tactics with this message.'],
  },
  'campaign.member': {
    method: 'correlation',
    rationale: 'The message shares template, infrastructure or indicators with other analysed messages.',
    limitations: 'Similarity, not proof; see the relationship evidence.',
    actions: [A.scope],
  },
};

/** Documentation for a finding id; dynamic ids ("content.intent.payment", "attachments.risky:ab12…") resolve by prefix. */
export function findingDoc(id: string): FindingDoc | null {
  if (DOCS[id]) return DOCS[id] as FindingDoc;
  const base = id.split(':')[0] as string;
  if (DOCS[base]) return DOCS[base] as FindingDoc;
  const parts = base.split('.');
  while (parts.length > 1) {
    parts.pop();
    const k = parts.join('.');
    if (DOCS[k]) return DOCS[k] as FindingDoc;
  }
  return null;
}

export function allFindingDocs(): Record<string, FindingDoc> {
  return { ...DOCS };
}
