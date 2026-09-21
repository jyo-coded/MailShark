// First-run experience: what MailShark does, the privacy promise, and the Gmail permission check.
import { render } from 'preact';
import { useEffect, useState } from 'preact/hooks';
import { ext } from '../shared/ext';
import { send } from '../shared/protocol';
import { useSettings } from '../ui/theme';
import { SharkMark } from '../ui/SharkMark';
import { SHARK_EYE, SHARK_GILLS, SHARK_PATH } from '../../brand/mark.mjs';
import { ArrowRight, Check, Inbox, LayoutDashboard, Lock, ScanEye, ShieldCheck } from '../ui/icons';

const GMAIL = { origins: ['https://mail.google.com/*'] };

function Ocean() {
  return (
    <svg class="ms-ocean" viewBox="0 0 720 150" aria-hidden="true">
      <defs>
        <linearGradient id="wl" x1="0" x2="1">
          <stop offset="0" stop-color="#38e1d6" stop-opacity="0" />
          <stop offset="0.2" stop-color="#38e1d6" stop-opacity="0.7" />
          <stop offset="0.8" stop-color="#3b9af6" stop-opacity="0.7" />
          <stop offset="1" stop-color="#6d5dfc" stop-opacity="0" />
        </linearGradient>
        <linearGradient id="fish" x1="0" y1="0" x2="64" y2="40" gradientUnits="userSpaceOnUse">
          <stop offset="0" stop-color="#f2fdff" />
          <stop offset="1" stop-color="#8eeff0" />
        </linearGradient>
      </defs>
      <g style={{ animation: 'ms-wave-32 3.2s linear infinite' }}>
        <path d="M-40 110 q16 -10 32 0 t32 0 t32 0 t32 0 t32 0 t32 0 t32 0 t32 0 t32 0 t32 0 t32 0 t32 0 t32 0 t32 0 t32 0 t32 0 t32 0 t32 0 t32 0 t32 0 t32 0 t32 0 t32 0 t32 0 t32 0" fill="none" stroke="url(#wl)" stroke-width="3" stroke-linecap="round" />
      </g>
      <g style={{ animation: 'ms-wave-32 5s linear infinite reverse', opacity: 0.45 }}>
        <path d="M-40 128 q16 -8 32 0 t32 0 t32 0 t32 0 t32 0 t32 0 t32 0 t32 0 t32 0 t32 0 t32 0 t32 0 t32 0 t32 0 t32 0 t32 0 t32 0 t32 0 t32 0 t32 0 t32 0 t32 0 t32 0 t32 0 t32 0" fill="none" stroke="url(#wl)" stroke-width="2" stroke-linecap="round" />
      </g>
      <g style={{ animation: 'ms-swim 9s cubic-bezier(.45,0,.55,1) infinite' }}>
        <g transform="translate(300 34) scale(1.9)">
          <g style={{ animation: 'ms-bob 2.4s ease-in-out infinite', transformBox: 'fill-box', transformOrigin: 'center' }}>
            <path d={SHARK_PATH} fill="url(#fish)" />
            <circle cx={SHARK_EYE.cx} cy={SHARK_EYE.cy} r={SHARK_EYE.r} fill="#0b1b33" />
            {SHARK_GILLS.map((d) => (
              <path d={d} fill="none" stroke="#0b1b33" stroke-opacity="0.5" stroke-width="0.9" stroke-linecap="round" />
            ))}
          </g>
        </g>
      </g>
    </svg>
  );
}

function Welcome() {
  useSettings();
  const [granted, setGranted] = useState<boolean | null>(null);
  useEffect(() => {
    void ext.permissions.contains(GMAIL).then(setGranted);
    const onAdded = (): void => void ext.permissions.contains(GMAIL).then(setGranted);
    ext.permissions.onAdded.addListener(onAdded);
    ext.permissions.onRemoved.addListener(onAdded);
    return () => {
      ext.permissions.onAdded.removeListener(onAdded);
      ext.permissions.onRemoved.removeListener(onAdded);
    };
  }, []);

  return (
    <div class="ms-welcome">
      <div class="ms-sea" />
      <div class="ms-hero">
        <SharkMark size={56} state="idle" />
        <span class="ms-chip ms-chip--accent">
          <ShieldCheck /> Installed · protection is on
        </span>
        <h1>
          Every email, <span class="ms-gradient-text">dissected.</span>
        </h1>
        <p>MailShark takes apart every email you open in Gmail (sender, route, links, attachments and wording), explains what it finds, and traces the campaigns behind it. All on your device.</p>
        <Ocean />
        <div class="ms-row" style={{ gap: '10px', flexWrap: 'wrap', justifyContent: 'center' }}>
          {granted === false ? (
            <button type="button" class="ms-btn ms-btn--primary ms-btn--lg" onClick={() => void ext.permissions.request(GMAIL).then(setGranted)}>
              <Lock /> Allow MailShark on Gmail
            </button>
          ) : (
            <a class="ms-btn ms-btn--primary ms-btn--lg" href="https://mail.google.com/" target="_blank" rel="noopener noreferrer">
              <Inbox /> Open Gmail <ArrowRight />
            </a>
          )}
          <button type="button" class="ms-btn ms-btn--lg" onClick={() => void send({ kind: 'openLab' })}>
            <LayoutDashboard /> Explore the Lab
          </button>
        </div>
        {granted === false && <div class="ms-faint" style={{ fontSize: '12.5px' }}>Firefox needs your OK before MailShark can read emails on mail.google.com.</div>}
        {granted === true && (
          <div class="ms-row ms-faint" style={{ fontSize: '12.5px', gap: '6px' }}>
            <Check size={14} color="var(--ms-safe)" /> Gmail access granted
          </div>
        )}
      </div>

      <div class="ms-steps ms-stagger">
        <div class="ms-step">
          <div class="ms-step-n">1</div>
          <h3>Open any email</h3>
          <p>MailShark fetches the original message (like “Download message”) straight into memory.</p>
        </div>
        <div class="ms-step">
          <div class="ms-step-n">2</div>
          <h3>Read the verdict</h3>
          <p>A banner appears above the email with a risk score and the reasons. Hit <b>Dissect</b> for the full forensic view.</p>
        </div>
        <div class="ms-step">
          <div class="ms-step-n">3</div>
          <h3>Stay a step ahead</h3>
          <p>Dangerous links are blocked, your inbox gets verdict badges, and related emails are traced into campaigns.</p>
        </div>
      </div>

      <div class="ms-privacy">
        <div class="ms-privacy-icon">
          <ScanEye />
        </div>
        <div>
          <b style={{ fontSize: '14.5px' }}>Your mail never leaves this browser.</b>
          <div class="ms-muted" style={{ fontSize: '13px' }}>
            No servers, no accounts, no analytics. The engine runs locally, and threat feeds are downloaded to you, not queried with your data.
          </div>
        </div>
        <button type="button" class="ms-btn" onClick={() => void send({ kind: 'openLab', route: 'about' })}>
          How it works
        </button>
      </div>
    </div>
  );
}

render(<Welcome />, document.getElementById('app') as HTMLElement);
