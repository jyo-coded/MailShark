import { useEffect, useState } from 'preact/hooks';
import type { Verdict } from '../../../../engine/src/types';
import { send, type ReportSummary } from '../../shared/protocol';
import { plural } from '../../shared/format';
import { Empty, Segmented, download } from '../../ui/primitives';
import { SharkMark } from '../../ui/SharkMark';
import { Download, Search } from '../../ui/icons';
import { MailRow, PageHead } from '../components';
import type { LabContext } from '../nav';

const PAGE = 40;

export function HistoryPage({ ctx }: { ctx: LabContext }) {
  const [verdict, setVerdict] = useState<Verdict | 'all'>('all');
  const [query, setQuery] = useState('');
  const [page, setPage] = useState(0);
  const [data, setData] = useState<{ items: ReportSummary[]; total: number } | null>(null);
  useEffect(() => {
    const t = setTimeout(() => void send({ kind: 'history', limit: PAGE, offset: page * PAGE, verdict, query }).then(setData), query ? 180 : 0);
    return () => clearTimeout(t);
  }, [verdict, query, page]);
  useEffect(() => setPage(0), [verdict, query]);
  const pages = data ? Math.max(1, Math.ceil(data.total / PAGE)) : 1;

  return (
    <>
      <PageHead
        eyebrow="Evidence locker"
        title="Mail history"
        actions={
          <button
            type="button"
            class="ms-btn"
            onClick={() =>
              void send({ kind: 'exportAll' }).then((r) => download(`mailshark-export-${new Date().toISOString().slice(0, 10)}.json`, r.json))
            }
          >
            <Download /> Export all
          </button>
        }
      >
        Every email MailShark has dissected, with its full forensic report, stored only in this browser.
      </PageHead>
      <div class="ms-row" style={{ marginBottom: '14px', gap: '10px' }}>
        <div class="ms-input-wrap ms-grow" style={{ maxWidth: '420px' }}>
          <Search />
          <input class="ms-input" type="search" placeholder="Search subject, sender or file…" value={query} onInput={(e) => setQuery((e.target as HTMLInputElement).value)} />
        </div>
        <Segmented
          label="Filter by verdict"
          value={verdict}
          onChange={setVerdict}
          options={[
            { value: 'all', label: 'All' },
            { value: 'danger', label: 'Phishing' },
            { value: 'caution', label: 'Suspicious' },
            { value: 'safe', label: 'Safe' },
          ]}
        />
        <div class="ms-grow" />
        {data && <span class="ms-faint" style={{ fontSize: '12.5px' }}>{plural(data.total, 'email')}</span>}
      </div>
      <div class="ms-panel">
        {data === null ? (
          <div style={{ padding: '16px' }} class="ms-col">
            {[0, 1, 2, 3].map(() => (
              <div class="ms-skeleton" style={{ height: '46px' }} />
            ))}
          </div>
        ) : data.items.length ? (
          <div class="ms-list">{data.items.map((s) => <MailRow s={s} onOpen={ctx.openReport} />)}</div>
        ) : (
          <Empty icon={<SharkMark size={52} state="idle" />} title={query || verdict !== 'all' ? 'Nothing matches' : 'No mail dissected yet'}>
            {query || verdict !== 'all' ? 'Try a different search or filter.' : 'Open Gmail and read an email, or import files in Analyze files.'}
          </Empty>
        )}
      </div>
      {pages > 1 && (
        <div class="ms-row" style={{ justifyContent: 'center', marginTop: '14px' }}>
          <button type="button" class="ms-btn ms-btn--sm" disabled={page === 0} onClick={() => setPage(page - 1)}>
            Previous
          </button>
          <span class="ms-faint" style={{ fontSize: '12.5px' }}>
            Page {page + 1} of {pages}
          </span>
          <button type="button" class="ms-btn ms-btn--sm" disabled={page + 1 >= pages} onClick={() => setPage(page + 1)}>
            Next
          </button>
        </div>
      )}
    </>
  );
}
