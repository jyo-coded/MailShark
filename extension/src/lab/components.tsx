import type { ComponentChildren } from 'preact';
import type { ReportSummary } from '../shared/protocol';
import { relativeTime } from '../shared/format';
import { Chip, VerdictIcon } from '../ui/primitives';
import { FileText, GitFork } from '../ui/icons';

export function PageHead({ eyebrow, title, children, actions }: { eyebrow?: string; title: ComponentChildren; children?: ComponentChildren; actions?: ComponentChildren }) {
  return (
    <div class="ms-page-head">
      <div>
        {eyebrow && <div class="ms-eyebrow">{eyebrow}</div>}
        <h1 class="ms-h1" style={{ marginTop: eyebrow ? '6px' : 0 }}>
          {title}
        </h1>
        {children && <p>{children}</p>}
      </div>
      {actions && <div class="ms-row">{actions}</div>}
    </div>
  );
}

export function Kpi({ icon, value, label, tone }: { icon: ComponentChildren; value: ComponentChildren; label: string; tone?: 'danger' | 'accent' | 'caution' | 'safe' }) {
  return (
    <div class="ms-kpi" data-tone={tone}>
      <div class="ms-kpi-icon">{icon}</div>
      <b>{value}</b>
      <span>{label}</span>
    </div>
  );
}

export function MailRow({ s, onOpen }: { s: ReportSummary; onOpen: (id: string) => void }) {
  return (
    <button type="button" class="ms-mailrow" onClick={() => onOpen(s.id)}>
      <div class="ms-verdict-dot" data-v={s.verdict}>
        <VerdictIcon verdict={s.verdict} size={17} />
      </div>
      <div style={{ minWidth: 0 }}>
        <div class="ms-mailrow-title ms-truncate">{s.subject || '(no subject)'}</div>
        <div class="ms-mailrow-sub ms-truncate">
          {s.fromName ? `${s.fromName} · ` : ''}
          {s.fromAddress || 'unknown sender'} · {s.oneLiner}
        </div>
      </div>
      <div class="ms-row" style={{ gap: '6px' }}>
        {s.source === 'file' && <Chip icon={<FileText />}>file</Chip>}
        {s.campaign && s.campaign.size > 1 && (
          <Chip tone="accent" icon={<GitFork />}>
            {s.campaign.id}
          </Chip>
        )}
        <Chip tone={s.verdict === 'safe' ? 'safe' : s.verdict}>{s.score}</Chip>
        <span class="ms-faint" style={{ fontSize: '11.5px', width: '64px', textAlign: 'right' }}>
          {relativeTime(s.storedAt)}
        </span>
      </div>
    </button>
  );
}
