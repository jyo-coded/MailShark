// Method & limits: how classes, confidence, correlation and intelligence work, with the live
// thresholds and the full finding catalogue served by the API (never a stale copy).
import { useState } from 'preact/hooks';
import { useApi } from '../lib/hooks';
import { human } from '../lib/format';
import type { FindingDoc } from '../lib/types';
import { Badge, ErrorBox, Loading, Panel } from '../components/ui';

interface Catalog {
  findings: Record<string, FindingDoc>;
  thresholds: { caution: number; danger: number; coverageFloor: number };
  correlation: { edgeThreshold: number; exactThreshold: number; resolution: number; maxCandidatesPerMessage: number; maxKeyFanout: number; families: Record<string, { base: number; label: string }> };
}

export function Docs() {
  const d = useApi<Catalog>('/api/catalog');
  const [q, setQ] = useState('');
  if (d.error) return <ErrorBox error={d.error} retry={d.reload} />;
  if (!d.data) return <Loading />;
  const t = d.data.thresholds;
  const cr = d.data.correlation;
  const findings = Object.entries(d.data.findings).filter(([id, f]) => !q || `${id} ${f.rationale} ${f.method}`.toLowerCase().includes(q.toLowerCase()));
  return (
    <div class="page" style={{ maxWidth: '1100px' }}>
      <div class="page-head">
        <div>
          <div class="eyebrow">Reference</div>
          <h1>Method &amp; limits</h1>
        </div>
      </div>
      <div class="col" style={{ gap: 'var(--sp-3)' }}>
        <Panel title="Classes">
          <table class="t compact">
            <tbody>
              <tr>
                <td style={{ width: '130px' }}>
                  <Badge c="malicious">Malicious</Badge>
                </td>
                <td class="wrap">Risk score ≥ {t.danger} <b>and</b> at least one high or critical finding (other than campaign correlation) or an intelligence match. A high score built only from many weak signals stays suspicious.</td>
              </tr>
              <tr>
                <td>
                  <Badge c="suspicious">Suspicious</Badge>
                </td>
                <td class="wrap">Risk score ≥ {t.caution}, or ≥ {t.danger} without a strong finding. Needs analyst review.</td>
              </tr>
              <tr>
                <td>
                  <Badge c="inconclusive">Inconclusive</Badge>
                </td>
                <td class="wrap">Below the suspicious threshold, but evidence coverage is under {Math.round(t.coverageFloor * 100)}% (e.g. no headers, no body, forwarded copy without routing). Too little evidence to call it benign.</td>
              </tr>
              <tr>
                <td>
                  <Badge c="benign">Benign</Badge>
                </td>
                <td class="wrap">Below the suspicious threshold with sufficient coverage. Benign means no indicator of malice was found in the available evidence, not that the message is proven safe.</td>
              </tr>
              <tr>
                <td>
                  <Badge c="failed">Failed</Badge>
                </td>
                <td class="wrap">The message could not be analysed (malformed beyond parsing, timeout, resource limit). The original evidence is preserved and the error is recorded.</td>
              </tr>
            </tbody>
          </table>
        </Panel>
        <Panel title="Confidence">
          <ul class="rationale" style={{ color: 'var(--text)' }}>
            <li>
              <b>Malicious:</b> high when medium-or-higher findings come from at least two independent categories (e.g. sender and links) and evidence coverage is ≥ 60%; low when coverage is under 40%; otherwise medium.
            </li>
            <li>
              <b>Suspicious:</b> never high (it is a request for review). Medium when the score is at least 10 points from both thresholds and coverage is ≥ 50%; otherwise low.
            </li>
            <li>
              <b>Benign:</b> high when the score is at least 20 points below the suspicious threshold, coverage is ≥ 80% and not a single risk finding above informational (low or higher) is present; low when the margin is under 10 points or coverage is under 60%; otherwise medium. Benign means nothing indicative was found in the available evidence, not that the message is proven safe.
            </li>
            <li>
              <b>Inconclusive:</b> always low.
            </li>
          </ul>
          <p class="small muted" style={{ marginTop: '8px' }}>
            Confidence describes how well the available evidence supports the class under these rules. It is not a calibrated probability. Benchmark results (precision, recall, false-positive rate) are documented in docs/platform/VALIDATION.md.
          </p>
        </Panel>
        <Panel title="Facts, inferences and external intelligence">
          <ul class="rationale" style={{ color: 'var(--text)' }}>
            <li>
              <b>Observed evidence</b>: values parsed from the message bytes (headers, route, authentication results as recorded, links, attachments, hashes). Original files are stored unchanged and re-verified by SHA-256 on every read.
            </li>
            <li>
              <b>Assessment</b>: engine inferences (findings, score, class, clusters). Each finding states its method (protocol check, heuristic, statistical, intelligence, correlation), rationale, limitations and recommended actions.
            </li>
            <li>
              <b>External intelligence</b>: what a third-party source reports about an indicator, with the source, match type and snapshot. A listing is information about the indicator, not proof about the message.
            </li>
          </ul>
          <p class="small muted" style={{ marginTop: '8px' }}>
            Hashing shows that the platform’s copy has not changed since intake. It does not establish how the evidence was collected, and this platform makes no claim of compliance with a forensic standard.
          </p>
        </Panel>
        <Panel title="Campaign correlation">
          <p class="small">
            Messages are compared on specificity-weighted shared indicators (combined by noisy-OR) and on layered similarity (content, URLs, attachments, infrastructure, sender, semantics, delivery), after neutralising infrastructure shared by large providers. Relationship score = 1 − (1 − indicators) × (1 − similarity).
          </p>
          <ul class="rationale" style={{ color: 'var(--text)' }}>
            <li>
              <b>Exact</b>: one artifact alone is strong enough (strength ≥ {cr.exactThreshold}), e.g. an identical attachment or Reply-To mailbox.
            </li>
            <li>
              <b>Probable</b>: combined evidence ≥ {cr.edgeThreshold}.
            </li>
            <li>
              <b>Clusters</b>: Louvain community detection over these edges (resolution {cr.resolution}). Clusters are local to a case.
            </li>
            <li>
              <b>External association</b>: <i>reported</i> when a strong, specific indicator is listed in a source event; <i>possible</i> when only weak overlaps exist. Never an attribution by itself.
            </li>
          </ul>
          <table class="t compact" style={{ marginTop: '8px' }}>
            <thead>
              <tr>
                <th>Indicator family</th>
                <th class="num" style={{ width: '120px' }}>
                  Base strength
                </th>
              </tr>
            </thead>
            <tbody>
              {Object.entries(cr.families)
                .sort((a, b) => b[1].base - a[1].base)
                .map(([k, v]) => (
                  <tr>
                    <td>
                      {v.label} <span class="mono xs faint">{k}</span>
                    </td>
                    <td class="num">{v.base.toFixed(2)}</td>
                  </tr>
                ))}
            </tbody>
          </table>
          <p class="xs faint" style={{ marginTop: '6px' }}>
            Base strengths are reduced for popular domains, shared platforms and indicators common across the case. Thresholds are set with MAILSHARK_CORR_EDGE, MAILSHARK_CORR_EXACT and MAILSHARK_CORR_RESOLUTION.
          </p>
        </Panel>
        <Panel title={`Finding catalogue (${Object.keys(d.data.findings).length})`} actions={<input class="input" placeholder="Filter" value={q} onInput={(e) => setQ((e.target as HTMLInputElement).value)} />} tight>
          <div class="table-wrap">
            <table class="t compact">
              <thead>
                <tr>
                  <th style={{ width: '230px' }}>Finding</th>
                  <th style={{ width: '100px' }}>Method</th>
                  <th>Rationale · limitations</th>
                  <th style={{ width: '140px' }}>ATT&amp;CK</th>
                </tr>
              </thead>
              <tbody>
                {findings.map(([id, f]) => (
                  <tr>
                    <td class="mono small wrap">{id}</td>
                    <td class="small">{human(f.method)}</td>
                    <td class="wrap small">
                      {f.rationale}
                      <div class="faint">Limits: {f.limitations}</div>
                    </td>
                    <td class="small mono wrap">{f.attack?.map((a) => a.id).join(', ') ?? '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>
      </div>
    </div>
  );
}
