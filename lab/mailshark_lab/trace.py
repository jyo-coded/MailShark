"""Campaign tracing: what every member shares, what the attacker rotated, and where it came from."""

from __future__ import annotations

from collections import Counter

import pandas as pd

ATTRIBUTES = [
    ("from_domain", "Sender domain"),
    ("from_name", "Sender name"),
    ("local_template", "Mailbox pattern"),
    ("reply_to_domain", "Reply-To domain"),
    ("origin_net", "Sending network"),
    ("origin_host_domain", "Sending server org"),
    ("x_mailer", "Mailer software"),
    ("dkim_domain", "DKIM signing domain"),
    ("header_order", "Header fingerprint"),
    ("msgid_template", "Message-ID pattern"),
    ("verp_campaign", "Bulk-mail campaign id"),
    ("subject_template", "Subject template"),
    ("html_skeleton", "HTML template"),
    ("intent", "Lure type"),
    ("link_domains", "Link domains"),
    ("url_paths", "Phishing-kit path"),
    ("attachment_sha256", "Attachment hash"),
    ("attachment_structs", "Attachment structure"),
]


def _key(v) -> str | None:
    if isinstance(v, (list, tuple, set)):
        return " + ".join(sorted(map(str, v))) if v else None
    if v is None or (isinstance(v, float) and pd.isna(v)) or v == "":
        return None
    return str(v)


def profile(members: pd.DataFrame) -> dict:
    """Invariants (identical across ≥60 % of members, ≥2 members) vs. rotated attributes."""
    size = len(members)
    invariants, rotated = [], []
    for col, label in ATTRIBUTES:
        values = [k for k in (_key(v) for v in members[col]) if k is not None]
        if not values:
            continue
        counts = Counter(values)
        top, n = counts.most_common(1)[0]
        entry = {"attribute": label, "distinct": len(counts), "coverage": round(len(values) / size, 2), "example": top[:120]}
        if len(counts) == 1 and n >= max(2, round(size * 0.6)):
            invariants.append(entry)
        elif len(counts) > 1:
            rotated.append(entry)
    dates = members["date"].dropna()
    ips = sorted({ip for ip in members["origin_ip"] if ip})
    return {
        "size": size,
        "invariants": invariants,
        "rotated": rotated,
        "attacker_cost": len(invariants),
        "first_seen": dates.min().isoformat() if not dates.empty else None,
        "last_seen": dates.max().isoformat() if not dates.empty else None,
        "senders": sorted({d for d in members["from_domain"] if d}),
        "origin_ips": ips,
        "origin_networks": sorted({n for n in members["origin_net"] if n}),
        "link_domains": sorted({d for ds in members["link_domains"] for d in ds}),
        "attachments": sorted({h for hs in members["attachment_sha256"] for h in hs}),
        "subjects": members["subject"].head(5).tolist(),
    }


def trace_all(msgs: pd.DataFrame, labels: pd.Series) -> list[dict]:
    """Profile every campaign (label ≥ 0), largest first."""
    df = msgs.assign(campaign=msgs["msg_id"].map(labels))
    out = []
    for cid, members in df[df["campaign"] >= 0].groupby("campaign"):
        p = profile(members)
        p["campaign"] = f"C-{int(cid):04d}"
        p["members"] = members["msg_id"].tolist()
        out.append(p)
    return sorted(out, key=lambda p: -p["size"])
