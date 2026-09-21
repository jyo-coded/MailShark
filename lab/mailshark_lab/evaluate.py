"""Validation: does campaign correlation survive indicator rotation better than IOC matching?

For every rotation level a labelled synthetic corpus is generated, both strategies cluster it, and
their output is scored against ground truth with pairwise precision / recall / F1 (did the method
put two emails of the same campaign together, and only those?) and the Adjusted Rand Index.
"""

from __future__ import annotations

import itertools
from pathlib import Path

import pandas as pd
from sklearn.metrics import adjusted_rand_score

from .cluster import cluster_campaigns, cluster_ioc
from .extract import extract
from .normalize import to_frames
from .synth import LEVELS, generate


def pairwise(truth: list[int], pred: list[int]) -> dict[str, float]:
    tp = fp = fn = 0
    for i, j in itertools.combinations(range(len(truth)), 2):
        same_t = truth[i] >= 0 and truth[i] == truth[j]
        same_p = pred[i] >= 0 and pred[i] == pred[j]
        tp += same_t and same_p
        fp += (not same_t) and same_p
        fn += same_t and (not same_p)
    p = tp / (tp + fp) if tp + fp else 1.0
    r = tp / (tp + fn) if tp + fn else 1.0
    return {"precision": round(p, 3), "recall": round(r, 3), "f1": round(2 * p * r / (p + r) if p + r else 0.0, 3)}


def _singletons(labels: list[int]) -> list[int]:
    """Give every unclustered item its own label so ARI treats it as a singleton."""
    out, nxt = [], max(labels + [0]) + 1
    for lab in labels:
        if lab < 0:
            out.append(nxt)
            nxt += 1
        else:
            out.append(lab)
    return out


def run(levels: list[str] | None = None, campaigns: int = 8, per_campaign: int = 12, background: int = 40, seed: int = 7) -> pd.DataFrame:
    rows = []
    for level in levels or LEVELS:
        samples = generate(level, campaigns, per_campaign, background, seed)
        items = [extract(f"s{i:04d}", s.raw) for i, s in enumerate(samples)]
        msgs, urls, _atts, sketches = to_frames(items)
        truth = [s.campaign for s in samples]
        ours, _ = cluster_campaigns(msgs, sketches)
        base = cluster_ioc(msgs, urls)
        for method, pred in (("IOC matching (baseline)", base), ("MailShark correlation", ours)):
            labels = [int(pred[m]) for m in msgs.msg_id]
            rows.append(
                {
                    "rotation": level,
                    "method": method,
                    **pairwise(truth, labels),
                    "ari": round(adjusted_rand_score(_singletons(truth), _singletons(labels)), 3),
                    "campaigns_found": len({lab for lab in labels if lab >= 0}),
                }
            )
    return pd.DataFrame(rows)


def chart(df: pd.DataFrame, path: Path) -> Path:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    fig, ax = plt.subplots(figsize=(8.5, 4.2), dpi=160)
    colors = {"IOC matching (baseline)": "#94a3b8", "MailShark correlation": "#0ea5a4"}
    for method, g in df.groupby("method", sort=False):
        ax.plot(g["rotation"], g["f1"], marker="o", linewidth=2.4, label=method, color=colors.get(method, "#333"))
    ax.set_ylim(0, 1.05)
    ax.set_ylabel("Pairwise F1 (campaign reconstruction)")
    ax.set_xlabel("Indicators rotated by the attacker")
    ax.set_title("Campaign detection as attackers rotate indicators")
    ax.grid(alpha=0.25)
    ax.spines[["top", "right"]].set_visible(False)
    ax.legend(frameon=False, loc="lower left")
    plt.setp(ax.get_xticklabels(), rotation=20, ha="right")
    fig.tight_layout()
    fig.savefig(path)
    plt.close(fig)
    return path
