import { VERSION } from '../../shared/ext';
import { SharkMark } from '../../ui/SharkMark';
import { Cpu, EyeOff, GitFork, Lock, ScanEye, ShieldCheck } from '../../ui/icons';
import { PageHead } from '../components';

const PROMISES = [
  { icon: <Cpu />, title: 'Analysis runs on your device', text: 'The forensic engine is bundled inside the extension. Emails are fetched from Gmail into memory, dissected, and never sent anywhere.' },
  { icon: <EyeOff />, title: 'No accounts, no tracking', text: 'MailShark has no servers that receive your data, no analytics and no ads. Firefox shows this at install: “collects no data”.' },
  { icon: <Lock />, title: 'Inert parsing', text: 'HTML is parsed, never rendered. Attachments are hashed and inspected as bytes, never opened. Remote images and links are never fetched.' },
  { icon: <ShieldCheck />, title: 'Threat feeds come to you', text: 'Public blocklists are downloaded as compact Bloom filters and checked locally, so no domain from your mail is ever looked up online.' },
];

export function AboutPage() {
  return (
    <>
      <PageHead eyebrow="Privacy & about" title="Built to see everything, and share nothing.">
        MailShark is an open-source forensic engine for email: a Wireshark for your inbox.
      </PageHead>
      <div class="ms-grid ms-grid-2 ms-stagger" style={{ maxWidth: '980px' }}>
        {PROMISES.map((p) => (
          <div class="ms-lesson">
            <div class="ms-lesson-icon">{p.icon}</div>
            <div class="ms-h3">{p.title}</div>
            <div class="ms-muted" style={{ fontSize: '13px' }}>
              {p.text}
            </div>
          </div>
        ))}
      </div>

      <div class="ms-panel" style={{ marginTop: '18px', maxWidth: '980px' }}>
        <div class="ms-panel-head">
          <span class="ms-h3">How a dissection works</span>
          <ScanEye size={16} class="ms-faint" />
        </div>
        <div class="ms-panel-body">
          <ol class="ms-muted" style={{ margin: 0, paddingLeft: '18px', fontSize: '13px', lineHeight: 1.8 }}>
            <li>You open an email in Gmail; MailShark requests the original message (the same file as Gmail’s “Download message”).</li>
            <li>The engine parses the MIME structure, headers, Received chain and authentication results written by Gmail.</li>
            <li>Sender identity, links, HTML, wording, attachments and QR codes are analysed against 60+ techniques.</li>
            <li>Findings are weighed into an explainable risk score; every conclusion links to its evidence.</li>
            <li>A privacy-preserving fingerprint links the email to campaigns, even when attackers rotate every indicator.</li>
          </ol>
        </div>
      </div>

      <div class="ms-panel" style={{ marginTop: '14px', maxWidth: '980px' }}>
        <div class="ms-panel-head">
          <span class="ms-h3">Version & credits</span>
          <GitFork size={16} class="ms-faint" />
        </div>
        <div class="ms-panel-body ms-row" style={{ gap: '16px', alignItems: 'flex-start' }}>
          <SharkMark size={56} state="idle" />
          <div class="ms-muted" style={{ fontSize: '13px' }}>
            <div>
              <b style={{ color: 'var(--ms-text)' }}>MailShark {VERSION}</b> · MIT licence ·{' '}
              <a href="https://github.com/jyo-coded/MailShark" target="_blank" rel="noopener noreferrer">
                github.com/jyo-coded/MailShark
              </a>
            </div>
            <div style={{ marginTop: '6px' }}>
              Built with Preact, postal-mime, htmlparser2, tldts (Public Suffix List), fflate, jsQR, d3-force, idb and Lucide icons. Typeface: Geist (SIL OFL). Detection research validated on the
              Nazario phishing corpus (CC BY 4.0) and the SpamAssassin public corpus.
            </div>
          </div>
        </div>
      </div>
    </>
  );
}
