// Security-awareness academy: short lessons tied to real techniques + a "spot the phish" drill.
import type { ComponentChildren } from 'preact';
import { useState } from 'preact/hooks';
import { Chip } from '../../ui/primitives';
import { SharkMark } from '../../ui/SharkMark';
import { AtSign, CircleCheck, FileArchive, GitFork, Link2, Lock, Phone, QrCode, Reply, RefreshCw, ShieldAlert, Target, Zap } from '../../ui/icons';
import { PageHead } from '../components';
import type { LabContext } from '../nav';

interface Lesson {
  icon: ComponentChildren;
  title: string;
  how: string;
  spot: string[];
  example: ComponentChildren;
}

const LESSONS: Lesson[] = [
  {
    icon: <Target />,
    title: 'Look-alike domains',
    how: 'Attackers register domains that read like a brand at a glance: swapped letters, digits for letters, or letters from other alphabets.',
    spot: ['Read the domain from the right: in paypal.com.secure-check.ru the real site is secure-check.ru.', 'Watch for rn↔m, 1↔l, 0↔o and odd hyphens.', 'MailShark flags homoglyphs, typosquats and brand decoys automatically.'],
    example: (
      <>
        <code>paypa1.com</code> · <code>rnicrosoft.com</code> · <code>pаypal.com</code> <span class="ms-faint">(Cyrillic “а”)</span>
      </>
    ),
  },
  {
    icon: <AtSign />,
    title: 'Display-name spoofing',
    how: 'The sender name is free text. “PayPal Service” can sit on top of any address.',
    spot: ['Always look at the address, not the name.', 'A brand name on a random or free-mail address is a red flag.', 'Addresses written inside the name field are a disguise.'],
    example: (
      <>
        <b>PayPal Service</b> <code>&lt;service@verify-center.xyz&gt;</code>
      </>
    ),
  },
  {
    icon: <Reply />,
    title: 'The Reply-To trap',
    how: 'Business-email-compromise emails look like they come from your boss or a supplier, but replies are routed to the attacker.',
    spot: ['Check where “Reply” would actually go.', 'Treat urgent payment or gift-card requests as suspicious by default.', 'Confirm through a phone number you already know, never one from the email.'],
    example: (
      <>
        From <code>ceo@acme-corp.co</code> → Reply-To <code>ceo.acme@gmail.com</code>
      </>
    ),
  },
  {
    icon: <Link2 />,
    title: 'Links that lie',
    how: 'The text of a link can show one website while the link opens another.',
    spot: ['Hover before you click: the real destination appears.', 'Shortened links and free web hosts hide who is behind the page.', 'MailShark’s link guard stops clicks on dangerous destinations.'],
    example: (
      <>
        Shows <code>https://www.paypal.com</code> → opens <code>paypa1-secure.com/login</code>
      </>
    ),
  },
  {
    icon: <FileArchive />,
    title: 'Booby-trapped attachments',
    how: 'Files that run code or open fake login pages: HTML/SVG files, disk images, password-protected zips, macro documents.',
    spot: ['Never “Enable content” or “Enable editing” on a document from email.', 'An .html, .svg, .iso or .img attachment is almost never legitimate.', '“invoice.pdf.exe” is an executable wearing a costume.'],
    example: (
      <>
        <code>Voicemail_00-47.html</code> · <code>Invoice.docm</code> · <code>scan.pdf.iso</code>
      </>
    ),
  },
  {
    icon: <QrCode />,
    title: 'QR-code phishing (“quishing”)',
    how: 'A QR code moves you from a protected computer to your phone, where links are harder to inspect.',
    spot: ['Be wary of QR codes asking you to log in, re-enroll MFA or pay.', 'Real IT teams rarely send QR codes by email.', 'MailShark decodes QR images and checks where they point.'],
    example: <>“Scan to keep your Microsoft 365 account active”</>,
  },
  {
    icon: <Zap />,
    title: 'Pressure tactics',
    how: 'Deadlines, threats and rewards are designed to make you act before you think.',
    spot: ['“Within 24 hours”, “final notice”, “account suspended” are classic triggers.', 'Legitimate services give you time and multiple channels.', 'When you feel rushed, slow down.'],
    example: <>“Your mailbox will be deleted today unless you verify immediately.”</>,
  },
  {
    icon: <Lock />,
    title: 'SPF, DKIM & DMARC in one minute',
    how: 'Receiving servers check whether the sending server and signature are authorized by the sender’s domain.',
    spot: ['DMARC fail on a well-known brand means the From address is forged.', 'Pass only proves which domain sent it, not that the domain is honest.', 'Attackers happily pass authentication for their own look-alike domains.'],
    example: (
      <>
        <code>dmarc=fail header.from=chase.com</code> → forged
      </>
    ),
  },
  {
    icon: <Phone />,
    title: 'Call-back scams',
    how: 'A fake invoice or renewal (“Norton”, “Geek Squad”) with a phone number: the “support agent” then asks for remote access or payment.',
    spot: ['Never call numbers from unexpected invoices.', 'Check your accounts directly in the official app or site.', 'MailShark highlights phone numbers used in these lures.'],
    example: <>“Your subscription renewed for $399.99. Call +1 (8xx) xxx-xxxx to cancel.”</>,
  },
  {
    icon: <GitFork />,
    title: 'Why campaigns matter',
    how: 'Attackers send the same lure from many senders, domains and IPs so each email looks new. The template, tooling and landing-page kit stay the same.',
    spot: ['Similar emails from different senders are a warning, not a coincidence.', 'MailShark links them into campaigns and shows what the attacker rotated.', 'Reporting one email helps expose the whole campaign.'],
    example: <>4 emails · 4 domains · 4 IPs → 1 campaign (same HTML template + kit path)</>,
  },
];

interface Question {
  fromName: string;
  from: string;
  subject: string;
  body: string;
  extra?: string;
  phish: boolean;
  why: string;
}

const QUIZ: Question[] = [
  { fromName: 'Microsoft 365', from: 'no-reply@m365-mailbox-security.com', subject: 'Mailbox storage full: messages on hold', body: 'Your mailbox is full. 12 incoming messages are on hold. Verify your account within 24 hours to release them.', extra: 'Button → m365-mailbox-security.com/owa', phish: true, why: 'Microsoft never mails you from m365-mailbox-security.com. Storage panic + “release your messages” is a classic credential lure.' },
  { fromName: 'GitHub', from: 'noreply@github.com', subject: '[GitHub] A new SSH key was added to your account', body: 'The following SSH key was added to your account. If you believe this key was added in error, you can remove it at github.com/settings/keys.', extra: 'DMARC pass · github.com', phish: false, why: 'Sent and authenticated by github.com, no pressure, and it points you to settings you can open yourself.' },
  { fromName: 'Rahul (CEO)', from: 'r.mehta@acme-corp.co', subject: 'Quick favor', body: 'Are you at your desk? I need you to buy 5 Google Play gift cards for a client. Keep this between us, I’m in a meeting.', extra: 'Reply-To: rahul.ceo.acme@gmail.com', phish: true, why: 'Gift cards + secrecy + a Reply-To that goes to Gmail: textbook CEO fraud.' },
  { fromName: 'DHL Express', from: 'track@dhl-parcel-redelivery.top', subject: 'Delivery failed: customs fee due', body: 'Your parcel is on hold. Pay the ₹49 customs fee to reschedule delivery.', extra: 'Link → dhl-parcel-redelivery.top/pay', phish: true, why: 'A .top look-alike domain asking for a small fee: the fee is bait to steal card details.' },
  { fromName: 'HDFC Bank InstaAlerts', from: 'alerts@hdfcbank.net', subject: 'Transaction alert for your credit card', body: 'Rs.1,250.00 was spent on your card ending 1234 at AMAZON. Never share your OTP or PIN with anyone.', extra: 'DMARC pass · hdfcbank.net', phish: false, why: 'Authenticated bank domain, no link or request: an informational alert.' },
  { fromName: 'Accounts Payable', from: 'accounts@invoices-portal.net', subject: 'Overdue invoice #INV-20931', body: 'Please find the invoice attached. The document is protected: click Enable Editing and Enable Content to view it.', extra: 'Attachment: INV-20931.docm', phish: true, why: 'A macro-enabled document that asks you to enable content is how most document malware starts.' },
  { fromName: 'Google', from: 'no-reply@accounts.google.com', subject: 'Security alert: new sign-in on Windows', body: 'Your Google Account was just signed in to from a new Windows device. If this was you, you don’t need to do anything.', extra: 'DMARC pass · google.com', phish: false, why: 'Genuine google.com, authenticated, and it asks for nothing. Check activity in your account yourself if unsure.' },
  { fromName: 'IT Service Desk', from: 'it-support@corp-helpdesk.online', subject: 'Re-enroll MFA today', body: 'Your multi-factor authentication expires today. Scan the QR code with your phone to stay signed in.', extra: 'Image: QR → mfa-reenroll.corp-helpdesk.online', phish: true, why: 'QR codes for “MFA re-enrollment” from an unknown .online domain are a common quishing play.' },
];

function Quiz() {
  const [i, setI] = useState(0);
  const [answer, setAnswer] = useState<boolean | null>(null);
  const [score, setScore] = useState(0);
  const done = i >= QUIZ.length;
  if (done)
    return (
      <div class="ms-quiz-card" style={{ textAlign: 'center' }}>
        <SharkMark size={64} state={score >= 6 ? 'safe' : 'caution'} />
        <div class="ms-h2" style={{ marginTop: '10px' }}>
          {score} / {QUIZ.length} spotted
        </div>
        <p class="ms-muted">{score === QUIZ.length ? 'Apex predator. Nothing gets past you.' : score >= 6 ? 'Sharp instincts. Review the ones you missed.' : 'Phishers count on quick glances. Take the lessons above and try again.'}</p>
        <button
          type="button"
          class="ms-btn ms-btn--primary"
          onClick={() => {
            setI(0);
            setScore(0);
            setAnswer(null);
          }}
        >
          <RefreshCw /> Try again
        </button>
      </div>
    );
  const q = QUIZ[i] as Question;
  const right = answer !== null && answer === q.phish;
  return (
    <div class="ms-quiz-card" data-result={answer === null ? undefined : right ? 'right' : 'wrong'}>
      <div class="ms-row" style={{ justifyContent: 'space-between' }}>
        <span class="ms-eyebrow">
          Email {i + 1} of {QUIZ.length}
        </span>
        <span class="ms-faint" style={{ fontSize: '12px' }}>
          score {score}
        </span>
      </div>
      <div class="ms-mock" style={{ marginTop: '10px' }}>
        <div>
          <b>{q.fromName}</b> <code>&lt;{q.from}&gt;</code>
        </div>
        <div style={{ fontWeight: 600, marginTop: '4px' }}>{q.subject}</div>
        <div class="ms-muted" style={{ marginTop: '4px' }}>
          {q.body}
        </div>
        {q.extra && (
          <div style={{ marginTop: '8px' }}>
            <Chip>{q.extra}</Chip>
          </div>
        )}
      </div>
      {answer === null ? (
        <div class="ms-quiz-opt">
          <button
            type="button"
            class="ms-btn ms-btn--danger"
            onClick={() => {
              setAnswer(true);
              if (q.phish) setScore(score + 1);
            }}
          >
            <ShieldAlert /> Phishing
          </button>
          <button
            type="button"
            class="ms-btn"
            onClick={() => {
              setAnswer(false);
              if (!q.phish) setScore(score + 1);
            }}
          >
            <CircleCheck /> Legitimate
          </button>
        </div>
      ) : (
        <div style={{ marginTop: '12px' }}>
          <b style={{ color: right ? 'var(--ms-safe)' : 'var(--ms-danger)' }}>{right ? 'Correct.' : 'Not quite.'}</b>{' '}
          <span class="ms-muted">
            This one is {q.phish ? 'phishing' : 'legitimate'}. {q.why}
          </span>
          <div style={{ marginTop: '12px' }}>
            <button
              type="button"
              class="ms-btn ms-btn--primary ms-btn--sm"
              onClick={() => {
                setI(i + 1);
                setAnswer(null);
              }}
            >
              {i + 1 === QUIZ.length ? 'See score' : 'Next email'}
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

export function AcademyPage(_: { ctx: LabContext }) {
  return (
    <>
      <PageHead eyebrow="Security awareness" title="MailShark Academy">
        Ten short lessons on how phishing actually works, and a drill to sharpen your eye. Every technique here is one MailShark detects for you.
      </PageHead>
      <div class="ms-grid ms-grid-main" style={{ alignItems: 'start' }}>
        <div class="ms-grid ms-grid-2 ms-stagger">
          {LESSONS.map((l) => (
            <div class="ms-lesson">
              <div class="ms-lesson-icon">{l.icon}</div>
              <div class="ms-h3">{l.title}</div>
              <div class="ms-muted" style={{ fontSize: '13px' }}>
                {l.how}
              </div>
              <div class="ms-mock">{l.example}</div>
              <ul>
                {l.spot.map((s) => (
                  <li>{s}</li>
                ))}
              </ul>
            </div>
          ))}
        </div>
        <div style={{ position: 'sticky', top: '24px' }}>
          <div class="ms-h3" style={{ marginBottom: '10px' }}>
            Spot the phish
          </div>
          <Quiz />
        </div>
      </div>
    </>
  );
}
