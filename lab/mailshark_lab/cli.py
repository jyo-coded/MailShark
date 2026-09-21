"""Command-line interface.

    mailshark-lab analyze <paths…> [--out DIR] [--limit N]   trace campaigns in .eml / .mbox evidence
    mailshark-lab evaluate [--out DIR]                        IOC matching vs. campaign correlation
    mailshark-lab synth --level multiple --out DIR            write a labelled synthetic corpus
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from .acquire import acquire
from .cluster import cluster_campaigns, cluster_ioc
from .extract import extract
from .normalize import to_frames
from .report import build_report, defang
from .trace import trace_all


def cmd_analyze(args: argparse.Namespace) -> int:
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    t0 = time.time()
    items, manifest = acquire(args.paths, limit=args.limit)
    print(f"[acquire] {len(items)} messages ({manifest.shape[0]} manifest rows)")
    extracted = []
    for ev in items:
        try:
            extracted.append(extract(ev.msg_id, ev.raw))
        except Exception as exc:  # noqa: BLE001 - one malformed message must not stop a case
            print(f"[extract] skipped {ev.source}: {exc}", file=sys.stderr)
    msgs, urls, atts, sketches = to_frames(extracted)
    print(f"[normalize] {len(msgs)} messages, {len(urls)} URLs, {len(atts)} attachments")
    labels, edges = cluster_campaigns(msgs, sketches, threshold=args.threshold) if len(msgs) else ({}, [])
    ioc = cluster_ioc(msgs, urls) if len(msgs) else {}
    campaigns = trace_all(msgs, labels) if len(msgs) else []
    print(f"[cluster] {len(campaigns)} campaigns; IOC baseline found {len({v for v in ioc.values if v >= 0}) if len(msgs) else 0} groups")
    msgs.assign(campaign=msgs.msg_id.map(labels), ioc_group=msgs.msg_id.map(ioc)).drop(columns=["text_preview"]).to_csv(out / "messages.csv", index=False)
    if not urls.empty:
        urls.assign(url=urls.url.map(defang)).to_csv(out / "urls.csv", index=False)
    atts.to_csv(out / "attachments.csv", index=False)
    manifest.to_csv(out / "manifest.csv", index=False)
    (out / "links.json").write_text(json.dumps(edges[:5000], indent=1, default=str), encoding="utf-8")
    path = build_report(out, msgs, manifest, campaigns, title=args.title)
    print(f"[report] {path}  ({time.time() - t0:.1f}s)")
    return 0


def cmd_evaluate(args: argparse.Namespace) -> int:
    from .evaluate import chart, run

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    df = run(campaigns=args.campaigns, per_campaign=args.per_campaign, background=args.background, seed=args.seed)
    df.to_csv(out / "evaluation.csv", index=False)
    png = chart(df, out / "rotation_f1.png")
    print(df.to_string(index=False))
    items, manifest = acquire([], limit=0)
    del items
    import pandas as pd

    build_report(out, pd.DataFrame(columns=["msg_id", "origin_ip"]), manifest, [], evaluation=df, chart=png, title="Validation: campaign correlation under indicator rotation")
    print(f"[report] {out / 'report.html'}")
    return 0


def cmd_synth(args: argparse.Namespace) -> int:
    from .synth import generate

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    samples = generate(args.level, args.campaigns, args.per_campaign, args.background, args.seed)
    truth = {}
    for i, s in enumerate(samples):
        name = f"{i:04d}.eml"
        (out / name).write_bytes(s.raw)
        truth[name] = s.campaign
    (out / "ground_truth.json").write_text(json.dumps(truth, indent=1), encoding="utf-8")
    print(f"[synth] {len(samples)} messages → {out}")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="mailshark-lab", description="Phishing campaign tracing for email forensics.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("analyze", help="trace campaigns in .eml files, folders and .mbox archives")
    a.add_argument("paths", nargs="+")
    a.add_argument("--out", default="out/case")
    a.add_argument("--limit", type=int, default=None)
    a.add_argument("--threshold", type=float, default=0.60)
    a.add_argument("--title", default="Phishing campaign trace")
    a.set_defaults(fn=cmd_analyze)
    e = sub.add_parser("evaluate", help="validate campaign correlation against the IOC-matching baseline")
    e.add_argument("--out", default="out/evaluation")
    e.add_argument("--campaigns", type=int, default=8)
    e.add_argument("--per-campaign", type=int, default=12)
    e.add_argument("--background", type=int, default=40)
    e.add_argument("--seed", type=int, default=7)
    e.set_defaults(fn=cmd_evaluate)
    s = sub.add_parser("synth", help="write a labelled synthetic corpus")
    s.add_argument("--level", default="multiple")
    s.add_argument("--out", default="out/synthetic")
    s.add_argument("--campaigns", type=int, default=8)
    s.add_argument("--per-campaign", type=int, default=12)
    s.add_argument("--background", type=int, default=40)
    s.add_argument("--seed", type=int, default=7)
    s.set_defaults(fn=cmd_synth)
    args = ap.parse_args(argv)
    return int(args.fn(args))


if __name__ == "__main__":
    sys.exit(main())
