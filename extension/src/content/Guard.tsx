// Link guard: intercepts clicks on dangerous links and explains where they really go.
import { useEffect, useRef } from 'preact/hooks';
import type { GuardLink } from '../shared/protocol';
import { SharkMark } from '../ui/SharkMark';
import { Chip } from '../ui/primitives';
import { LINK_FLAGS, flagLabel } from '../ui/labels';
import { ExternalLink, ShieldCheck } from '../ui/icons';

function highlight(url: string, host: string, reg: string | null) {
  const i = url.indexOf(host);
  if (!reg || i < 0) return <>{url}</>;
  const j = i + host.length - reg.length;
  return (
    <>
      {url.slice(0, j)}
      <mark>{url.slice(j, i + host.length)}</mark>
      {url.slice(i + host.length)}
    </>
  );
}

export function Guard({ link, onBack, onProceed }: { link: GuardLink; onBack: () => void; onProceed: () => void }) {
  const back = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    back.current?.focus();
    const onKey = (e: KeyboardEvent): void => {
      if (e.key === 'Escape') onBack();
    };
    window.addEventListener('keydown', onKey, true);
    return () => window.removeEventListener('keydown', onKey, true);
  }, [onBack]);
  const flags = link.flags.filter((f) => flagLabel(LINK_FLAGS, f)[1] === 'danger' || flagLabel(LINK_FLAGS, f)[1] === 'caution');
  return (
    <div class="ms-guard-scrim" onClick={onBack}>
      <div class="ms-guard" role="alertdialog" aria-modal="true" aria-labelledby="ms-guard-title" onClick={(e) => e.stopPropagation()}>
        <div class="ms-guard-top">
          <SharkMark size={48} state="danger" />
          <div>
            <h2 id="ms-guard-title">Hold on: this link looks dangerous</h2>
            <p>MailShark stopped this click so you can check where it really leads.</p>
          </div>
        </div>
        <div class="ms-guard-body">
          {link.displayText && link.displayText.trim() !== link.url && (
            <div class="ms-guard-dest">
              <span class="ms-eyebrow">The email shows</span>
              <code>{link.displayText}</code>
            </div>
          )}
          <div class="ms-guard-dest">
            <span class="ms-eyebrow">It actually opens</span>
            <code>{highlight(link.url, link.host, link.regDomain)}</code>
          </div>
          <div class="ms-row" style={{ flexWrap: 'wrap', gap: '5px' }}>
            {link.intelHit && <Chip tone="danger">Listed in {link.intelHit}</Chip>}
            {link.lookalikeOf && <Chip tone="danger">Imitates {link.lookalikeOf}</Chip>}
            {flags.map((f) => {
              const [label, tone] = flagLabel(LINK_FLAGS, f);
              return <Chip tone={tone}>{label}</Chip>;
            })}
          </div>
        </div>
        <div class="ms-guard-actions">
          <button type="button" class="ms-btn ms-btn--ghost ms-btn--sm" onClick={onProceed}>
            <ExternalLink /> Open anyway
          </button>
          <button type="button" ref={back} class="ms-btn ms-btn--primary" onClick={onBack}>
            <ShieldCheck /> Take me back to safety
          </button>
        </div>
      </div>
    </div>
  );
}

export function HoverCard({ link, x, y }: { link: GuardLink; x: number; y: number }) {
  const left = Math.min(x + 14, window.innerWidth - 400);
  const top = Math.min(y + 18, window.innerHeight - 90);
  const tone = link.risk >= 3 ? 'ms-v-danger' : 'ms-v-caution';
  return (
    <div class={`ms-hc ${tone}`} style={{ left: `${Math.max(8, left)}px`, top: `${Math.max(8, top)}px` }}>
      <b>
        <SharkMark size={16} state={link.risk >= 3 ? 'danger' : 'caution'} badge={false} still />
        {link.risk >= 3 ? 'Dangerous link' : 'Suspicious link'}
      </b>
      <code>{link.url.length > 160 ? link.url.slice(0, 159) + '…' : link.url}</code>
    </div>
  );
}
