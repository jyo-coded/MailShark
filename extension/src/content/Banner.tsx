// In-email verdict banner.
import { useState } from 'preact/hooks';
import type { ReportSummary } from '../shared/protocol';
import { Scanner, SharkMark } from '../ui/SharkMark';
import { ScoreRing } from '../ui/ScoreRing';
import { Chip, SeverityIcon } from '../ui/primitives';
import { ChevronDown, GitFork, RefreshCw, ScanEye, X } from '../ui/icons';

export type BannerState =
  | { status: 'scan' }
  | { status: 'error'; message: string }
  | { status: 'done'; summary: ReportSummary };

export interface BannerProps {
  state: BannerState;
  safeMode: 'full' | 'compact' | 'hidden';
  onDissect: () => void;
  onRetry: () => void;
  onDismiss: () => void;
}

export function Banner({ state, safeMode, onDissect, onRetry, onDismiss }: BannerProps) {
  const [open, setOpen] = useState(false);

  if (state.status === 'scan') {
    return (
      <div class="ms-bn-wrap" aria-live="polite">
        <div class="ms-bn">
          <div class="ms-bn-icon">
            <span class="ms-ping" />
            <SharkMark size={34} state="scan" />
          </div>
          <div class="ms-bn-text">
            <div class="ms-bn-title" style={{ color: 'var(--ms-text)' }}>
              Dissecting this email…
            </div>
            <div class="ms-bn-sub">Headers, route, links and attachments are checked right here in your browser.</div>
            <div class="ms-bn-scan">
              <Scanner width={240} />
            </div>
          </div>
          <div />
        </div>
      </div>
    );
  }

  if (state.status === 'error') {
    return (
      <div class="ms-bn-wrap">
        <div class="ms-bn">
          <div class="ms-bn-icon">
            <SharkMark size={34} state="idle" />
          </div>
          <div class="ms-bn-text">
            <div class="ms-bn-title" style={{ color: 'var(--ms-text)' }}>
              MailShark couldn’t read this email
            </div>
            <div class="ms-bn-sub">{state.message}</div>
          </div>
          <div class="ms-bn-actions">
            <button type="button" class="ms-btn ms-btn--sm" onClick={onRetry}>
              <RefreshCw /> Retry
            </button>
            <button type="button" class="ms-btn ms-btn--ghost ms-btn--sm ms-btn--icon" aria-label="Dismiss" onClick={onDismiss}>
              <X />
            </button>
          </div>
        </div>
      </div>
    );
  }

  const s = state.summary;
  if (s.verdict === 'safe' && safeMode === 'hidden') return null;
  if (s.verdict === 'safe' && safeMode === 'compact' && !open) {
    const trust = s.top.find((t) => t.weight < 0);
    return (
      <div class="ms-bn-wrap" style={{ maxWidth: '560px' }}>
        <div class="ms-bn ms-bn--compact">
          <div class="ms-bn-icon">
            <SharkMark size={22} state="safe" />
          </div>
          <div class="ms-bn-text ms-row" style={{ gap: '8px' }}>
            <span class="ms-bn-title">{s.headline}</span>
            <span class="ms-bn-sub ms-truncate">{trust?.title ?? s.oneLiner}</span>
          </div>
          <button type="button" class="ms-btn ms-btn--ghost ms-btn--sm" onClick={onDissect}>
            <ScanEye /> Dissect
          </button>
        </div>
      </div>
    );
  }

  const warnings = s.top.filter((t) => t.weight > 0);
  return (
    <div class="ms-bn-wrap" aria-live="polite">
      <div class="ms-bn" role="status">
        <div class="ms-bn-icon">
          <ScoreRing score={s.score} verdict={s.verdict} size={44} stroke={4.5} />
        </div>
        <div class="ms-bn-text">
          <div class="ms-bn-title">
            {s.headline}
            <span class="ms-bn-brand">MailShark</span>
          </div>
          <div class="ms-bn-sub">{s.oneLiner}</div>
          {(warnings.length > 1 || s.campaign) && (
            <div class="ms-bn-chips">
              {warnings.slice(1, 3).map((w) => (
                <Chip tone={w.severity === 'critical' || w.severity === 'high' ? 'danger' : w.severity === 'medium' ? 'caution' : 'info'}>{w.title}</Chip>
              ))}
              {s.campaign && s.campaign.size > 1 && (
                <Chip tone="accent" icon={<GitFork />}>
                  Campaign {s.campaign.id} · {s.campaign.size} emails
                </Chip>
              )}
            </div>
          )}
          {open && (
            <div class="ms-bn-more">
              {s.top.map((t) => (
                <div class="ms-bn-more-item" data-sev={t.severity} data-trust={t.weight < 0 ? '' : undefined}>
                  <SeverityIcon severity={t.severity} trust={t.weight < 0} />
                  <span>
                    <b>{t.title}</b>
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
        <div class="ms-bn-actions">
          <button type="button" class="ms-btn ms-btn--primary ms-btn--sm" onClick={onDissect}>
            <ScanEye /> Dissect
          </button>
          <button type="button" class="ms-btn ms-btn--ghost ms-btn--sm ms-btn--icon" aria-label={open ? 'Show less' : 'Show reasons'} aria-expanded={open} onClick={() => setOpen(!open)}>
            <ChevronDown style={{ transform: open ? 'rotate(180deg)' : undefined, transition: 'transform 220ms' }} />
          </button>
          <button type="button" class="ms-btn ms-btn--ghost ms-btn--sm ms-btn--icon" aria-label="Hide for this email" onClick={onDismiss}>
            <X />
          </button>
        </div>
      </div>
    </div>
  );
}
