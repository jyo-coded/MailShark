// Golden fixtures: realistic phishing playbooks and legitimate mail, with the verdict each must get.
import { zipSync } from 'fflate';
import { buildEml, gmailReceived } from './mime';
import { QR_PNG_BASE64 } from './qr-png';
import type { Verdict } from '../../src/types';

export interface Fixture {
  name: string;
  expect: Verdict;
  mustInclude?: string[]; // finding id prefixes that must be present
  mustExclude?: string[];
  eml: () => string;
}

const DATE = 'Mon, 21 Sep 2026 15:48:59 +0000';

export const FIXTURES: Fixture[] = [
  {
    name: 'legit-newsletter',
    expect: 'safe',
    mustInclude: ['auth.dmarc-pass', 'route.esp'],
    mustExclude: ['sender.brand-impersonation'],
    eml: () =>
      buildEml({
        headers: [
          ...gmailReceived({ ip: '167.89.12.34', host: 'o1.ptr1234.news.example-weekly.com', auth: 'dkim=pass header.i=@example-weekly.com header.s=s1 header.b=abc; spf=pass (google.com: domain of bounces+123@em.example-weekly.com designates 167.89.12.34 as permitted sender) smtp.mailfrom="bounces+123@em.example-weekly.com"; dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=example-weekly.com' }),
          ['DKIM-Signature', 'v=1; a=rsa-sha256; c=relaxed/relaxed; d=example-weekly.com; h=content-type:from:mime-version:subject:list-unsubscribe:to; s=s1; bh=abc=; b=def='],
          ['From', 'The Weekly Digest <digest@example-weekly.com>'],
          ['To', 'victim@gmail.com'],
          ['Subject', 'Your Monday reading list: 7 stories'],
          ['Date', DATE],
          ['Message-ID', '<abc123def456@geopod-ismtpd-3>'],
          ['List-Unsubscribe', '<https://u123.ct.sendgrid.net/unsub?x=1>, <mailto:unsub@example-weekly.com>'],
          ['List-Unsubscribe-Post', 'List-Unsubscribe=One-Click'],
          ['X-SG-EID', 'u001.abcdef'],
        ],
        text: 'Good morning! Here are this week\'s stories. Read online at https://www.example-weekly.com/issues/412 . Unsubscribe: https://u123.ct.sendgrid.net/unsub?x=1',
        html: '<html><body><table class="wrapper"><tr><td class="content"><h1>Your Monday reading list</h1><p>Good morning! Here are seven stories we loved this week about science, design and the people behind them.</p><p><a href="https://u123.ct.sendgrid.net/ls/click?upn=abc">Read the issue</a></p><p class="footer"><a href="https://u123.ct.sendgrid.net/unsub?x=1">Unsubscribe</a></p><img src="https://u123.ct.sendgrid.net/wf/open?upn=xyz" width="1" height="1" alt=""></td></tr></table></body></html>',
      }),
  },
  {
    name: 'paypal-lookalike-credential',
    expect: 'danger',
    mustInclude: ['sender.brand-impersonation', 'links.text-mismatch'],
    eml: () =>
      buildEml({
        headers: [
          ...gmailReceived({ ip: '45.133.1.77', host: 'vps77.hostingcheap.ru', auth: 'spf=softfail (google.com: domain of transitioning service@paypa1-secure.com does not designate 45.133.1.77 as permitted sender) smtp.mailfrom=service@paypa1-secure.com; dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=paypa1-secure.com', spfLine: 'softfail (google.com: domain of transitioning service@paypa1-secure.com does not designate 45.133.1.77 as permitted sender)' }),
          ['From', '"PayPal Service" <service@paypa1-secure.com>'],
          ['To', 'victim@gmail.com'],
          ['Subject', 'Action required: your account has been limited'],
          ['Date', DATE],
          ['Message-ID', '<20260921154859.1234@paypa1-secure.com>'],
          ['X-Mailer', 'PHPMailer 6.8.1 (https://github.com/PHPMailer/PHPMailer)'],
        ],
        html: '<html><body><p>Dear Customer,</p><p>We noticed unusual activity on your account. Your account will be suspended within 24 hours unless you verify your identity.</p><p><a href="https://paypa1-secure.com/webscr/login?session=9f8a7b6c5d4e3f2a1b0c">https://www.paypal.com/signin</a></p><p>PayPal Security Team</p></body></html>',
      }),
  },
  {
    name: 'html-smuggling-voicemail',
    expect: 'danger',
    mustInclude: ['attachments.html-phish'],
    eml: () =>
      buildEml({
        headers: [
          ...gmailReceived({ ip: '185.222.58.9', host: 'mail.fax-notify.top', auth: 'spf=pass (google.com: domain of noreply@fax-notify.top designates 185.222.58.9 as permitted sender) smtp.mailfrom=noreply@fax-notify.top; dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=fax-notify.top' }),
          ['From', 'Microsoft 365 Voicemail <noreply@fax-notify.top>'],
          ['To', 'victim@gmail.com'],
          ['Subject', 'You have a new voicemail (00:47) - Listen now'],
          ['Date', DATE],
          ['Message-ID', '<vm-88213@fax-notify.top>'],
        ],
        html: '<html><body><p>You received a new voice message. Open the attached file to listen.</p></body></html>',
        attachments: [
          {
            filename: 'VM_Playback_00-47.html',
            contentType: 'text/html',
            content: '<html><head><script>var p=atob("PGZvcm0+");document.write(p);</script></head><body><form action="https://login-m365.fax-notify.top/owa.php"><input type="email" name="u"><input type="password" name="p"><button>Sign in</button></form></body></html>',
          },
        ],
      }),
  },
  {
    name: 'bec-giftcard-replyto',
    expect: 'danger',
    mustInclude: ['sender.reply-to-freemail'],
    eml: () =>
      buildEml({
        headers: [
          ...gmailReceived({ ip: '209.85.220.41', host: 'mail-sor-f41.google.com', auth: 'dkim=pass header.i=@gmail.com header.s=20230601 header.b=abc; spf=pass (google.com: domain of ceo.acmecorp@gmail.com designates 209.85.220.41 as permitted sender) smtp.mailfrom=ceo.acmecorp@gmail.com; dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com' }),
          ['From', 'Rahul Mehta <r.mehta@acme-corp.co>'],
          ['Reply-To', 'rahul.mehta.ceo@gmail.com'],
          ['To', 'finance@acmecorp.com'],
          ['Subject', 'Quick favor'],
          ['Date', DATE],
          ['Message-ID', '<CAxyz123@mail.gmail.com>'],
        ],
        text: 'Are you at your desk? I need a quick favor. I am in a meeting and need you to purchase gift cards for a client. Keep this between us for now. Reply with your cell number and I will send the details.\n\nRahul',
      }),
  },
  {
    name: 'macro-invoice',
    expect: 'danger',
    mustInclude: ['attachments.active-content', 'content.enable-content'],
    eml: () => {
      const docm = zipSync({
        '[Content_Types].xml': new TextEncoder().encode('<?xml version="1.0"?><Types/>'),
        'word/document.xml': new TextEncoder().encode('<w:document><w:body><w:p><w:r><w:t>Enable content to view invoice</w:t></w:r></w:p></w:body></w:document>'),
        'word/vbaProject.bin': new Uint8Array([0xd0, 0xcf, 0x11, 0xe0, 1, 2, 3, 4]),
        'word/_rels/document.xml.rels': new TextEncoder().encode('<Relationships><Relationship Id="rId1" Type="x/image" Target="media/image1.png"/></Relationships>'),
      });
      return buildEml({
        headers: [
          ...gmailReceived({ ip: '91.92.240.13', host: 'unknown', auth: 'spf=neutral (google.com: 91.92.240.13 is neither permitted nor denied by best guess record for domain of accounts@invoices-portal.net) smtp.mailfrom=accounts@invoices-portal.net' }),
          ['From', 'Accounts Payable <accounts@invoices-portal.net>'],
          ['To', 'victim@gmail.com'],
          ['Subject', 'Overdue invoice #INV-20931 - payment overdue'],
          ['Date', DATE],
          ['Message-ID', '<inv20931.77@invoices-portal.net>'],
        ],
        text: 'Hello,\n\nPlease find attached the outstanding invoice. The document is protected: please click Enable Editing and Enable Content to view it. Payment overdue, settle the payment immediately.\n\nRegards',
        attachments: [{ filename: 'INV-20931.docm', contentType: 'application/vnd.ms-word.document.macroEnabled.12', content: docm }],
      });
    },
  },
  {
    name: 'chase-domain-spoof-dmarc-fail',
    expect: 'danger',
    mustInclude: ['auth.dmarc-fail', 'sender.brand-impersonation'],
    eml: () =>
      buildEml({
        headers: [
          ...gmailReceived({ ip: '103.44.12.9', host: 'smtp.bulkmailer.biz', auth: 'spf=fail (google.com: domain of alerts@chase.com does not designate 103.44.12.9 as permitted sender) smtp.mailfrom=alerts@chase.com; dmarc=fail (p=REJECT sp=REJECT dis=QUARANTINE) header.from=chase.com', spfLine: 'fail (google.com: domain of alerts@chase.com does not designate 103.44.12.9 as permitted sender)' }),
          ['From', 'Chase Alert <alerts@chase.com>'],
          ['To', 'victim@gmail.com'],
          ['Subject', 'Security alert: unauthorized transaction'],
          ['Date', DATE],
          ['Message-ID', '<55555@smtp.bulkmailer.biz>'],
        ],
        html: '<p>We detected an unauthorized transaction. Confirm your identity immediately to avoid your account being locked.</p><p><a href="http://45.133.1.80/chase/verify.php">Verify now</a></p>',
      }),
  },
  {
    name: 'fake-reply-invoice',
    expect: 'caution',
    mustInclude: ['content.fake-reply'],
    eml: () =>
      buildEml({
        headers: [
          ...gmailReceived({ ip: '52.100.5.5', host: 'mail-eopbgr.outbound.protection.outlook.com', auth: 'dkim=pass header.i=@tradeco-intl.com header.s=selector1 header.b=abc; spf=pass (google.com: domain of billing@tradeco-intl.com designates 52.100.5.5 as permitted sender) smtp.mailfrom=billing@tradeco-intl.com; dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=tradeco-intl.com' }),
          ['From', 'Billing <billing@tradeco-intl.com>'],
          ['To', 'victim@gmail.com'],
          ['Subject', 'RE: Updated bank details for payment'],
          ['Date', DATE],
          ['Message-ID', '<AM0PR01MB1234@tradeco-intl.com>'],
        ],
        text: 'Hi,\n\nAs discussed, please note our new bank account for all future payments. Kindly update your records and process the pending payment via wire transfer to the IBAN below.\n\nIBAN: GB33BUKB20201555555555\n\nThanks',
      }),
  },
  {
    name: 'verified-bank-alert',
    expect: 'safe',
    mustInclude: ['sender.verified-brand'],
    mustExclude: ['sender.brand-impersonation'],
    eml: () =>
      buildEml({
        headers: [
          ...gmailReceived({ ip: '175.100.160.21', host: 'mailout.hdfcbank.net', auth: 'dkim=pass header.i=@hdfcbank.net header.s=hdfc header.b=abc; spf=pass (google.com: domain of alerts@hdfcbank.net designates 175.100.160.21 as permitted sender) smtp.mailfrom=alerts@hdfcbank.net; dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=hdfcbank.net' }),
          ['DKIM-Signature', 'v=1; a=rsa-sha256; d=hdfcbank.net; s=hdfc; h=from:to:subject:date; bh=x=; b=y='],
          ['From', 'HDFC Bank InstaAlerts <alerts@hdfcbank.net>'],
          ['To', 'victim@gmail.com'],
          ['Subject', 'Transaction alert for your HDFC Bank Credit Card'],
          ['Date', DATE],
          ['Message-ID', '<1790005.123@hdfcbank.net>'],
        ],
        text: 'Dear Customer, Rs.1,250.00 was spent on your HDFC Bank Credit Card ending 1234 at AMAZON on 21-09-2026. If you did not make this transaction, call 18002586161. Never share your OTP or PIN with anyone.',
      }),
  },
  {
    name: 'quishing-qr',
    expect: 'danger',
    mustInclude: ['attachments.qr'],
    eml: () =>
      buildEml({
        headers: [
          ...gmailReceived({ ip: '194.26.29.4', host: 'smtp.hr-portal-docs.com', auth: 'spf=pass (google.com: domain of hr@hr-portal-docs.com designates 194.26.29.4 as permitted sender) smtp.mailfrom=hr@hr-portal-docs.com; dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=hr-portal-docs.com' }),
          ['From', 'Microsoft Authenticator <hr@hr-portal-docs.com>'],
          ['To', 'victim@gmail.com'],
          ['Subject', 'Action required: re-enroll multi-factor authentication'],
          ['Date', DATE],
          ['Message-ID', '<mfa-1@hr-portal-docs.com>'],
        ],
        html: '<p>Your MFA enrollment expires today. Scan the QR code with your phone camera to keep your account active.</p><img src="cid:qr1" alt="QR">',
        attachments: [{ filename: 'qr.png', contentType: 'image/png', content: Uint8Array.from(Buffer.from(QR_PNG_BASE64, 'base64')), inline: true, cid: 'qr1' }],
      }),
  },
  {
    name: 'recruiter-brand-claim',
    expect: 'caution',
    mustInclude: ['sender.brand-impersonation', 'route.esp'],
    eml: () =>
      buildEml({
        headers: [
          ...gmailReceived({ ip: '103.197.16.155', host: 'mail.cb1155.mlrctk.com', returnPath: 'bounce.cli26174-1634010-1634010-2428252109-2056-3@mlrctk.com', auth: 'dkim=pass header.i=@hiring.talentsjobs.in header.s=mc header.b=abc; dkim=pass header.i=@mailercloud.com header.s=mc1 header.b=def; spf=pass (google.com: domain of bounce.cli26174-1634010-1634010@mlrctk.com designates 103.197.16.155 as permitted sender) smtp.mailfrom=bounce.cli26174-1634010-1634010@mlrctk.com; dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=hiring.talentsjobs.in' }),
          ['DKIM-Signature', 'v=1; a=rsa-sha256; d=hiring.talentsjobs.in; s=mc; h=from:to:subject; bh=x=; b=y='],
          ['DKIM-Signature', 'v=1; a=rsa-sha256; d=mailercloud.com; s=mc1; h=from:to:subject; bh=x=; b=y='],
          ['From', '"Mind Tree Placement Team" <noreply@hiring.talentsjobs.in>'],
          ['Reply-To', 'noreply@hiring.talentsjobs.in'],
          ['To', 'victim@gmail.com'],
          ['Subject', 'LTI Mind Tree Hiring 2027 – Frontend Developer, Software Engineer | Stipend Up to ₹40K'],
          ['Date', DATE],
          ['Message-ID', '<1790005743-MjQyODI1MjEwOS0xNjM0MDEw@hiring.talentsjobs.in>'],
          ['X-Mailer', 'mailercloud'],
          ['List-Unsubscribe', '<https://hiring.talentsjobs.in/un/cWbxEMSfsbsMkgUea>'],
        ],
        html: '<p>Dear Student,</p><p>We are pleased to inform you about an exciting Mind TREE Jobs and Internship Hiring Drive for eligible students from your institution.</p><p><a href="https://hiring.talentsjobs.in/links/cWbxEMSfsbsMkgUeaZMBwDeaBaqCaFWMVXhcaMDaea/4101188">APPLY NOW</a></p><img src="https://hiring.talentsjobs.in/opens/cWbxEMSfsbsMkg/blank.gif" width="1" height="1">',
      }),
  },
];
