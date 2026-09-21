import { useEffect, useState } from 'preact/hooks';
import { sendOr, type CampaignRecord, type ReportSummary } from '../../shared/protocol';
import { plural, relativeTime } from '../../shared/format';
import { Chip, Empty, Segmented, VerdictIcon } from '../../ui/primitives';
import { SharkMark } from '../../ui/SharkMark';
import { CampaignPanel } from '../../ui/dissector/panels';
import { ArrowRight, GitFork, Lock, Shuffle } from '../../ui/icons';
import { PageHead } from '../components';
import { CampaignGraph } from '../Graph';
import { go, type LabContext } from '../nav';

export function CampaignCard({ c }: { c: CampaignRecord }) {
  const p = c.profile;
  return (
    <button type="button" class="ms-camp-card" data-v={c.verdict} onClick={() => go('campaigns', c.id)}>
      <div class="ms-row" style={{ justifyContent: 'space-between' }}>
        <span class="ms-camp-id">{c.id}</span>
        <Chip tone={c.verdict} icon={<VerdictIcon verdict={c.verdict} size={12} />}>
          {c.verdict === 'danger' ? 'Threat' : c.verdict === 'caution' ? 'Suspicious' : 'Bulk'}
        </Chip>
      </div>
      <div class="ms-h3" style={{ minHeight: '40px' }}>
        {c.label}
      </div>
      <div class="ms-row" style={{ flexWrap: 'wrap', gap: '5px' }}>
        <Chip>{plural(c.members.length, 'email')}</Chip>
        {p.rotated.length > 0 && <Chip tone="caution" icon={<Shuffle />}>{p.rotated.length} rotated</Chip>}
        {p.invariants.length > 0 && <Chip tone="accent" icon={<Lock />}>{p.invariants.length} stable</Chip>}
      </div>
      <div class="ms-row ms-faint" style={{ fontSize: '12px', justifyContent: 'space-between' }}>
        <span>last seen {relativeTime(p.lastSeen || c.updatedAt)}</span>
        <ArrowRight size={14} />
      </div>
    </button>
  );
}

function Detail({ id, ctx }: { id: string; ctx: LabContext }) {
  const [data, setData] = useState<{ campaign: CampaignRecord; members: ReportSummary[] } | null | undefined>(undefined);
  useEffect(() => {
    void sendOr({ kind: 'campaign', id }, null).then(setData);
  }, [id]);
  if (data === undefined) return <div class="ms-skeleton" style={{ height: '420px' }} />;
  if (data === null)
    return (
      <Empty icon={<GitFork size={28} />} title="Campaign not found">
        It may have been merged into another campaign.{' '}
        <button type="button" class="ms-btn ms-btn--sm" onClick={() => go('campaigns')}>
          Back to campaigns
        </button>
      </Empty>
    );
  const c = data.campaign;
  return (
    <>
      <PageHead
        eyebrow={`Campaign ${c.id}`}
        title={c.label}
        actions={
          <button type="button" class="ms-btn" onClick={() => go('campaigns')}>
            All campaigns
          </button>
        }
      >
        {plural(c.members.length, 'email')} linked by shared templates, infrastructure and landing pages · max risk {c.maxScore}/100
      </PageHead>
      <div class="ms-grid ms-grid-main">
        <div class="ms-panel">
          <div class="ms-panel-head">
            <span class="ms-h3">Relationship graph</span>
            <span class="ms-faint" style={{ fontSize: '12px' }}>
              click an email to dissect it
            </span>
          </div>
          <div class="ms-panel-body">
            <CampaignGraph memberIds={c.members} onOpen={ctx.openReport} />
          </div>
        </div>
        <div class="ms-panel">
          <div class="ms-panel-body">
            <CampaignPanel campaign={c} members={data.members} currentId="" onOpen={ctx.openReport} />
          </div>
        </div>
      </div>
    </>
  );
}

export function CampaignsPage({ ctx, selected }: { ctx: LabContext; selected: string | null }) {
  const [list, setList] = useState<CampaignRecord[] | null>(null);
  const [filter, setFilter] = useState<'threats' | 'all' | 'bulk'>('threats');
  useEffect(() => {
    if (!selected) void sendOr({ kind: 'campaigns' }, []).then(setList);
  }, [selected]);
  if (selected) return <Detail id={selected} ctx={ctx} />;
  const shown = (list ?? []).filter((c) => (filter === 'all' ? true : filter === 'threats' ? c.verdict !== 'safe' : c.verdict === 'safe'));
  return (
    <>
      <PageHead
        eyebrow="Campaign tracing"
        title="Campaigns"
        actions={
          <Segmented
            label="Filter campaigns"
            value={filter}
            onChange={setFilter}
            options={[
              { value: 'threats', label: 'Threats' },
              { value: 'bulk', label: 'Bulk senders' },
              { value: 'all', label: 'All' },
            ]}
          />
        }
      >
        Attackers rotate senders, domains, IPs and file hashes to look like strangers. MailShark links their emails by what they can’t easily change: templates, tooling, landing-page kits and infrastructure habits.
      </PageHead>
      {list === null ? (
        <div class="ms-grid ms-grid-3">
          {[0, 1, 2].map(() => (
            <div class="ms-skeleton" style={{ height: '150px', borderRadius: '18px' }} />
          ))}
        </div>
      ) : shown.length ? (
        <div class="ms-grid ms-grid-3 ms-stagger">
          {shown.map((c) => (
            <CampaignCard c={c} />
          ))}
        </div>
      ) : (
        <Empty icon={<SharkMark size={52} state="idle" />} title={filter === 'threats' ? 'No threat campaigns traced' : 'No campaigns yet'}>
          Campaigns appear when two or more emails share a common origin. The more mail MailShark dissects, the sharper the picture gets. Tip: import an .mbox in <b>Analyze files</b> to trace campaigns across a whole mailbox.
        </Empty>
      )}
    </>
  );
}
