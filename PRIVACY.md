# MailShark privacy policy

_Last updated: 22 September 2026 · applies to MailShark 1.0.0 and later_

MailShark analyses your email **on your own device**. It has no servers, no accounts, no analytics and no telemetry. No email content, address, link or verdict is ever sent to the MailShark authors or to anyone else.

## What MailShark reads

- **Messages you open in Gmail.** When you open an email at `mail.google.com`, MailShark asks Gmail for that message's original source. This is the same data as Gmail's *Show original*, requested from Gmail in your existing browser session. It is analysed in the extension's background page.
- **Messages visible in your inbox list** (optional, **Settings → Scan unopened emails**). MailShark can scan unopened messages that are on screen, so risky ones get a badge before you open them.
- **Files you drop on the Analyze page** (`.eml` / `.mbox`). These are read and analysed locally.

MailShark reads mail only on `https://mail.google.com/`. It has no access to any other website.

## What MailShark stores

Analysis results are stored in the extension's own IndexedDB database in your browser profile:
- verdict and findings
- subject, sender, link addresses and attachment names and hashes
- campaign fingerprints

The raw message itself is **not** stored.
- Storage is capped at 4,000 reports; the oldest safe reports are removed first.
- Your settings are stored in the extension's local storage.
- **Settings → Erase all data** deletes everything immediately. Uninstalling the extension also removes it.

## Network connections

MailShark makes exactly two kinds of network requests:

| Destination | Why | What is sent |
|---|---|---|
| `https://mail.google.com/` | To fetch the source of a message you opened (or, with *Scan unopened emails*, one on screen) | A normal Gmail request with your existing Gmail cookies. It goes only to Google, which already holds the message. |
| `https://raw.githubusercontent.com/jyo-coded/MailShark/feeds/v1/` | To download public threat-intelligence lists (compiled Bloom filters) every 12 hours | A plain file download, sent **without cookies**. No information about your mail is included. Domains are checked against the downloaded lists locally. Turn this off in **Settings → Public threat feeds**. |

As with any download, GitHub receives the connecting IP address and browser user agent. See [GitHub's privacy statement](https://docs.github.com/site-policy/privacy-policies/github-general-privacy-statement).

MailShark never:
- opens links or attachments from your mail
- loads remote images
- contacts the sender
- submits anything to scanners, reputation services or AI APIs

## Permissions

| Permission | Why it is needed |
|---|---|
| Access to `mail.google.com` | Show the verdict banner, inspector and inbox badges inside Gmail, and fetch the source of the messages being analysed |
| `storage`, `unlimitedStorage` | Keep settings and the local evidence database (reports and campaigns) on your device |
| `alarms` | Refresh the public threat feeds periodically |

In Firefox's data-collection disclosure, MailShark declares that it collects **no data** (`data_collection_permissions: none`).

## Children

MailShark does not knowingly process information about children beyond the email the user themselves opens, and it collects nothing.

## Changes and contact

Changes to this policy will appear in this file and in the [changelog](CHANGELOG.md). Questions: open an issue at https://github.com/jyo-coded/MailShark/issues.
