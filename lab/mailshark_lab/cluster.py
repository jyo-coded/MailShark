"""Campaign correlation: similarity over equality.

Two strategies are implemented so they can be compared (see evaluate.py):

* ``cluster_ioc``: the traditional baseline. Messages are linked only when they share an *exact*
  indicator (sender address/domain, sending IP, URL, link domain or attachment hash).
* ``cluster_campaigns``: MailShark's approach. Candidates are retrieved through an inverted index
  of stable traits plus MinHash-LSH over the text, then scored with a layered similarity that
  survives indicator rotation (templates, tooling, infrastructure habits, kit paths).
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

import networkx as nx
import pandas as pd
from datasketch import MinHash, MinHashLSH

# Shared by everybody, so sharing them proves nothing: excluded from linking in both methods.
UBIQUITOUS = {
    "gmail.com", "googlemail.com", "yahoo.com", "outlook.com", "hotmail.com", "live.com", "aol.com", "icloud.com", "mail.ru", "yandex.ru",
    "google.com", "microsoft.com", "facebook.com", "twitter.com", "x.com", "instagram.com", "linkedin.com", "youtube.com", "apple.com",
    "w3.org", "schema.org", "gstatic.com", "googleapis.com", "amazonaws.com", "cloudfront.net", "akamaihd.net", "wikipedia.org",
}

LAYER_WEIGHTS = {"content": 0.22, "urls": 0.18, "attachments": 0.15, "infra": 0.17, "sender": 0.10, "semantic": 0.10, "delivery": 0.08}
JOIN_THRESHOLD = 0.60


def _jaccard(a: set | list, b: set | list) -> float | None:
    a, b = set(a), set(b)
    if not a and not b:
        return None
    return len(a & b) / len(a | b)


def _eq(a, b) -> float | None:
    if not a or not b:
        return None
    return 1.0 if a == b else 0.0


def _weighted(parts: list[tuple[float | None, float]]) -> float | None:
    num = den = 0.0
    for v, w in parts:
        if v is None:
            continue
        num += v * w
        den += w
    return num / den if den else None


@dataclass
class Similarity:
    score: float
    layers: dict[str, float | None]
    hard_link: str | None


def similarity(a, b, mh_a: MinHash, mh_b: MinHash) -> Similarity:
    """Layered similarity between two message rows (namedtuples or Series from normalize.to_frames)."""
    text = mh_a.jaccard(mh_b)
    subj = 1.0 if a.subject_template and a.subject_template == b.subject_template else (_jaccard(a.subject_template.split(), b.subject_template.split()) or 0.0)
    content = _weighted([(text, 0.5), (subj, 0.25), (_eq(a.html_skeleton, b.html_skeleton), 0.25)])

    dom = _jaccard(a.link_domains, b.link_domains)
    tpl = _jaccard(a.url_templates, b.url_templates)
    path = _jaccard(a.url_paths, b.url_paths)
    urls = None if dom is None and tpl is None else max(tpl or 0.0, (dom or 0.0) * 0.85, (path or 0.0) * 0.8)

    attachments = None
    if a.attachment_sha256 or b.attachment_sha256:
        if set(a.attachment_sha256) & set(b.attachment_sha256):
            attachments = 1.0
        else:
            structs = (_jaccard(a.attachment_structs, b.attachment_structs) or 0.0) * 0.85
            fuzzy = 0.0
            try:  # ssdeep similarity catches repacked/modified files
                import ppdeep

                for x in a.attachment_ssdeep:
                    for y in b.attachment_ssdeep:
                        fuzzy = max(fuzzy, ppdeep.compare(x, y) / 100)
            except ImportError:  # pragma: no cover
                pass
            attachments = max(structs, fuzzy * 0.9)

    infra = _weighted(
        [
            (_eq(a.origin_net, b.origin_net), 0.2),
            (_eq(a.origin_host_domain, b.origin_host_domain), 0.1),
            (_eq(a.x_mailer, b.x_mailer), 0.15),
            (_eq(a.dkim_domain, b.dkim_domain), 0.15),
            (_eq(a.dkim_selectors, b.dkim_selectors), 0.05),
            (_eq(a.header_order, b.header_order), 0.2),
            (_eq(a.msgid_template, b.msgid_template), 0.15),
        ]
    )
    sender = _weighted(
        [
            (_eq(a.from_domain, b.from_domain), 0.35),
            (_eq(a.local_template, b.local_template), 0.15),
            (_eq(a.from_name.lower(), b.from_name.lower()), 0.3),
            (_eq(a.reply_to_domain, b.reply_to_domain), 0.2),
        ]
    )
    semantic = _weighted([(_eq(a.intent, b.intent), 0.6), (_eq(a.brand, b.brand), 0.4)]) if (a.intent or b.intent) else None
    delivery = None
    if pd.notna(a.date) and pd.notna(b.date):
        days = abs((a.date - b.date).total_seconds()) / 86400
        delivery = pow(2.718281828, -days / 3)

    layers = {"content": content, "urls": urls, "attachments": attachments, "infra": infra, "sender": sender, "semantic": semantic, "delivery": delivery}
    num = den = 0.0
    for k, v in layers.items():
        if v is None:
            continue
        num += v * LAYER_WEIGHTS[k]
        den += LAYER_WEIGHTS[k]
    score = num / den if den else 0.0

    hard = None
    if a.verp_campaign and a.verp_campaign == b.verp_campaign:
        hard = "same bulk-mail campaign id"
    elif set(a.attachment_sha256) & set(b.attachment_sha256):
        hard = "identical attachment (SHA-256)"
    elif text >= 0.9 and subj >= 0.8:
        hard = "near-identical text"
    elif a.url_templates and tpl is not None and tpl >= 0.8 and text >= 0.5:
        hard = "same landing-page pattern"
    if hard:
        score = max(score, 0.9)
    return Similarity(round(score, 3), layers, hard)


def _index_keys(r) -> list[str]:
    keys = []
    if r.verp_campaign:
        keys.append("verp:" + r.verp_campaign)
    if r.origin_net:
        keys.append("net:" + r.origin_net)
    if r.html_skeleton:
        keys.append("skel:" + r.html_skeleton)
    if len(r.subject_template) >= 8:
        keys.append("subj:" + r.subject_template)
    keys += ["att:" + h for h in r.attachment_sha256]
    keys += ["atts:" + s for s in r.attachment_structs]
    keys += ["dom:" + d for d in r.link_domains[:10] if d not in UBIQUITOUS]
    keys += ["path:" + p for p in r.url_paths[:10]]
    if r.from_domain and r.from_domain not in UBIQUITOUS:
        keys.append("from:" + r.from_domain)
    if r.header_order and r.x_mailer:
        keys.append(f"tool:{r.header_order}:{r.x_mailer}")
    return keys


def cluster_campaigns(msgs: pd.DataFrame, sketches: dict[str, MinHash], threshold: float = JOIN_THRESHOLD, max_fanout: int = 200) -> tuple[pd.Series, list[dict]]:
    """Assign campaign ids. Returns (msg_id → cluster label or -1, list of linked pairs with evidence)."""
    rows = {r.msg_id: r for r in msgs.itertuples(index=False)}
    lsh = MinHashLSH(threshold=0.5, num_perm=next(iter(sketches.values())).hashvalues.size if sketches else 64)
    index: dict[str, list[str]] = defaultdict(list)
    graph = nx.Graph()
    graph.add_nodes_from(rows)
    edges: list[dict] = []
    for mid, r in rows.items():
        series = r  # namedtuple: same attribute access as a Series, far cheaper per pair
        candidates: dict[str, int] = defaultdict(int)
        for k in _index_keys(series):
            bucket = index[k]
            for other in bucket[-max_fanout:]:
                candidates[other] += 1
            bucket.append(mid)
        for other in lsh.query(sketches[mid]):
            candidates[other] += 1
        lsh.insert(mid, sketches[mid])
        for other, _ in sorted(candidates.items(), key=lambda kv: -kv[1])[:300]:
            sim = similarity(series, rows[other], sketches[mid], sketches[other])
            if sim.score >= threshold:
                graph.add_edge(mid, other, weight=sim.score)
                edges.append({"a": mid, "b": other, "score": sim.score, "hard_link": sim.hard_link, **{f"layer_{k}": v for k, v in sim.layers.items()}})
    labels = {}
    for i, comp in enumerate(sorted((c for c in nx.connected_components(graph) if len(c) > 1), key=len, reverse=True)):
        for mid in comp:
            labels[mid] = i
    return pd.Series({mid: labels.get(mid, -1) for mid in rows}, name="campaign"), edges


def cluster_ioc(msgs: pd.DataFrame, urls: pd.DataFrame | None = None) -> pd.Series:
    """Baseline: link messages that share any exact IOC."""
    graph = nx.Graph()
    graph.add_nodes_from(msgs.msg_id)
    owner: dict[str, str] = {}

    def link(key: str, mid: str) -> None:
        if not key or key.endswith(":"):
            return
        if key in owner:
            graph.add_edge(owner[key], mid)
        else:
            owner[key] = mid

    url_map: dict[str, list[str]] = defaultdict(list)
    if urls is not None and not urls.empty:
        for r in urls.itertuples(index=False):
            url_map[r.msg_id].append(r.url)
    for r in msgs.itertuples(index=False):
        link("addr:" + r.from_addr, r.msg_id)
        if r.from_domain not in UBIQUITOUS:
            link("fromdom:" + r.from_domain, r.msg_id)
        link("ip:" + r.origin_ip, r.msg_id)
        for d in r.link_domains:
            if d not in UBIQUITOUS:
                link("dom:" + d, r.msg_id)
        for h in r.attachment_sha256:
            link("sha:" + h, r.msg_id)
        for u in url_map.get(r.msg_id, []):
            link("url:" + u, r.msg_id)
    labels = {}
    for i, comp in enumerate(c for c in nx.connected_components(graph) if len(c) > 1):
        for mid in comp:
            labels[mid] = i
    return pd.Series({mid: labels.get(mid, -1) for mid in msgs.msg_id}, name="ioc_cluster")
