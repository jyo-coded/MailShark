"""Self-contained HTML case report (no external assets) + CSV evidence tables."""

from __future__ import annotations

import base64
import html
import json
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

from . import __version__

CSS = """
:root{--bg:#07101c;--card:#0e1726;--line:#1f2b3d;--text:#e6eef9;--muted:#93a3ba;--accent:#38e1d6;--danger:#ff5c77;--ok:#34d399;--warn:#fbbf24}
@media (prefers-color-scheme: light){:root{--bg:#f5f7fb;--card:#fff;--line:#e3e8f0;--text:#0b1322;--muted:#5b6679;--accent:#0b9e98;--danger:#e11d48;--ok:#059669;--warn:#b45309}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.55 "Segoe UI",system-ui,-apple-system,sans-serif}
main{max-width:1100px;margin:0 auto;padding:32px 20px 64px}h1{font-size:30px;margin:0 0 4px;letter-spacing:-.02em}h2{font-size:20px;margin:36px 0 12px}
.muted{color:var(--muted)}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;margin-top:18px}
.kpi{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:14px}.kpi b{display:block;font-size:26px;letter-spacing:-.03em}
.card{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:18px;margin-top:14px}
.chip{display:inline-block;padding:2px 9px;margin:2px 4px 2px 0;border-radius:99px;font-size:12px;border:1px solid var(--line)}
.inv{color:var(--accent);border-color:var(--accent)}.rot{color:var(--warn);border-color:var(--warn)}
table{width:100%;border-collapse:collapse;font-size:12.5px;margin-top:8px}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.05em}code{font-family:Consolas,ui-monospace,monospace;font-size:12px;word-break:break-all}
img{max-width:100%;border-radius:12px;background:#fff}
"""


def _esc(v) -> str:
    return html.escape("" if v is None else str(v))


def _chips(items: list[dict], cls: str) -> str:
    if not items:
        return '<span class="muted">none</span>'
    return "".join(f'<span class="chip {cls}" title="{_esc(i["example"])}">{_esc(i["attribute"])}{" ×" + str(i["distinct"]) if cls == "rot" else ""}</span>' for i in items)


def build_report(out: Path, msgs: pd.DataFrame, manifest: pd.DataFrame, campaigns: list[dict], evaluation: pd.DataFrame | None = None, chart: Path | None = None, title: str = "Phishing campaign trace") -> Path:
    out.mkdir(parents=True, exist_ok=True)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    clustered = sum(c["size"] for c in campaigns)
    parts = [
        f"<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>{_esc(title)}</title><style>{CSS}</style></head><body><main>",
        f"<div class='muted'>MailShark Lab {__version__} · generated {now}</div><h1>{_esc(title)}</h1>",
        "<p class='muted'>Acquisition → analysis → validation → report. Every message was hashed at intake; URLs are shown defanged.</p>",
        "<div class='grid'>",
        f"<div class='kpi'><b>{len(msgs)}</b><span class='muted'>messages analysed</span></div>",
        f"<div class='kpi'><b>{len(campaigns)}</b><span class='muted'>campaigns traced</span></div>",
        f"<div class='kpi'><b>{clustered}</b><span class='muted'>messages linked to a campaign</span></div>",
        f"<div class='kpi'><b>{msgs['origin_ip'].replace('', pd.NA).nunique()}</b><span class='muted'>distinct origin IPs</span></div>",
        "</div>",
    ]
    if evaluation is not None and not evaluation.empty:
        parts.append("<h2>Validation: campaign correlation vs. IOC matching</h2>")
        if chart and chart.exists():
            parts.append(f"<img alt='F1 by rotation level' src='data:image/png;base64,{base64.b64encode(chart.read_bytes()).decode()}'>")
        parts.append("<table><tr><th>Rotation</th><th>Method</th><th>Precision</th><th>Recall</th><th>F1</th><th>ARI</th><th>Campaigns</th></tr>")
        for r in evaluation.itertuples(index=False):
            parts.append(f"<tr><td>{_esc(r.rotation)}</td><td>{_esc(r.method)}</td><td>{r.precision:.3f}</td><td>{r.recall:.3f}</td><td><b>{r.f1:.3f}</b></td><td>{r.ari:.3f}</td><td>{r.campaigns_found}</td></tr>")
        parts.append("</table>")
    parts.append("<h2>Traced campaigns</h2>")
    if not campaigns:
        parts.append("<div class='card muted'>No two messages shared enough evidence to be linked.</div>")
    by_id = msgs.set_index("msg_id")
    for c in campaigns[:60]:
        members = by_id.loc[c["members"]]
        parts.append(
            f"<div class='card'><div style='display:flex;justify-content:space-between;gap:12px'><b style='font-size:16px'>{_esc(c['campaign'])} · {c['size']} messages</b>"
            f"<span class='muted'>{_esc((c['first_seen'] or '')[:10])} → {_esc((c['last_seen'] or '')[:10])}</span></div>"
            f"<p class='muted' style='margin:6px 0'>Attacker cost to evade: {c['attacker_cost']} stable traits · {len(c['senders'])} sender domains · {len(c['origin_ips'])} origin IPs · {len(c['link_domains'])} link domains</p>"
            f"<div><b>Stayed the same:</b> {_chips(c['invariants'], 'inv')}</div><div style='margin-top:4px'><b>Rotated:</b> {_chips(c['rotated'], 'rot')}</div>"
            "<table><tr><th>Date</th><th>From</th><th>Subject</th><th>Origin IP</th><th>SHA-256 (evidence)</th></tr>"
            + "".join(
                f"<tr><td>{_esc(str(m.date)[:16])}</td><td>{_esc(m.from_addr)}</td><td>{_esc(m.subject[:90])}</td><td><code>{_esc(m.origin_ip)}</code></td><td><code>{_esc(mid[:16])}…</code></td></tr>"
                for mid, m in members.head(25).iterrows()
            )
            + "</table></div>"
        )
    parts.append("<h2>Chain of custody</h2><table><tr><th>Source</th><th>Message SHA-256</th><th>Container SHA-256</th><th>Size</th></tr>")
    for r in manifest.head(500).itertuples(index=False):
        parts.append(f"<tr><td><code>{_esc(getattr(r, 'source', ''))}</code></td><td><code>{_esc(getattr(r, 'msg_id', ''))}</code></td><td><code>{_esc(getattr(r, 'container_sha256', ''))}</code></td><td>{_esc(getattr(r, 'size', ''))}</td></tr>")
    parts.append("</table></main></body></html>")
    path = out / "report.html"
    path.write_text("".join(parts), encoding="utf-8")
    (out / "campaigns.json").write_text(json.dumps(campaigns, indent=2, default=str), encoding="utf-8")
    return path


def defang(url: str) -> str:
    return url.replace("http", "hxxp", 1).replace(".", "[.]")
