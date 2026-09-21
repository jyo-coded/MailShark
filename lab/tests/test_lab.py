"""Tests for the MailShark Lab pipeline (acquisition → analysis → validation → report)."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pandas as pd
import pytest

from mailshark_lab.acquire import acquire
from mailshark_lab.cluster import cluster_campaigns, cluster_ioc
from mailshark_lab.evaluate import pairwise, run
from mailshark_lab.extract import extract, parse_auth_results, parse_received
from mailshark_lab.normalize import registrable, subject_template, to_frames, url_template
from mailshark_lab.report import build_report
from mailshark_lab.trace import trace_all

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "eml"


@pytest.fixture(scope="module")
def corpus():
    items, manifest = acquire([FIXTURES])
    extracted = {Path(ev.source).stem: extract(ev.msg_id, ev.raw) for ev in items}
    return items, manifest, extracted


def test_acquisition_hashes_every_message(corpus):
    items, manifest, _ = corpus
    assert len(items) == len(list(FIXTURES.glob("*.eml")))
    for ev in items:
        assert ev.msg_id == hashlib.sha256(ev.raw).hexdigest()
    assert {"msg_id", "container_sha256", "md5", "sha1"} <= set(manifest.columns)


def test_route_and_auth(corpus):
    _, _, ex = corpus
    rec = ex["recruiter-brand-claim"]
    assert rec.origin_ip == "103.197.16.155"
    assert rec.auth["dmarc"] == "pass"
    assert rec.verp_campaign == "26174:1634010"
    hop = parse_received("from mail.x.example (mail.x.example. [198.51.100.7]) by mx.google.com with ESMTPS id 1; Mon, 21 Sep 2026 08:49:05 -0700")
    assert hop.from_ip == "198.51.100.7" and hop.by_host == "mx.google.com"
    assert parse_auth_results("mx.google.com; spf=fail smtp.mailfrom=a@b.com; dmarc=fail header.from=chase.com")["dmarc"] == "fail"


def test_attachment_hashes_match_hashlib(corpus):
    items, _, ex = corpus
    att = ex["macro-invoice"].attachments[0]
    assert att.filename == "INV-20931.docm"
    assert att.detected == "zip" and any(e.endswith("vbaProject.bin") for e in att.zip_entries)
    assert len(att.sha256) == 64 and len(att.md5) == 32


def test_normalization_templates():
    assert registrable("a.b.example.co.uk") == "example.co.uk"
    reg, tpl, path = url_template("https://hiring.talentsjobs.in/links/cWbxEMSfsbsMkgUeaZMBwDeaBaqCaFWMVXhcaMDaea/4101188")
    assert (reg, path) == ("talentsjobs.in", "/links/{tok}/{n}")
    assert subject_template("Invoice #INV-20931 due 21/09/2026") == "invoice #inv-{n} due {date}"


def test_campaign_variants_are_linked_but_ioc_matching_misses_them(corpus):
    _, _, ex = corpus
    msgs, urls, _, sketches = to_frames(list(ex.values()))
    labels, edges = cluster_campaigns(msgs, sketches)
    sharepoint = [e.msg_id for k, e in ex.items() if k.startswith("campaign-sharepoint")]
    assert len({labels[m] for m in sharepoint}) == 1 and labels[sharepoint[0]] >= 0
    ioc = cluster_ioc(msgs, urls)
    assert len({ioc[m] for m in sharepoint}) > 1 or ioc[sharepoint[0]] == -1
    others = [e.msg_id for k, e in ex.items() if not k.startswith("campaign-sharepoint")]
    assert all(labels[m] == -1 or labels[m] != labels[sharepoint[0]] for m in others)
    profile = trace_all(msgs, labels)[0]
    assert {"Sender name", "HTML template"} <= {i["attribute"] for i in profile["invariants"]}
    assert "Sender domain" in {r["attribute"] for r in profile["rotated"]}


def test_pairwise_metrics():
    assert pairwise([0, 0, 1, 1], [0, 0, 1, 1]) == {"precision": 1.0, "recall": 1.0, "f1": 1.0}
    assert pairwise([0, 0, -1], [-1, -1, -1])["recall"] == 0.0


def test_rotation_experiment_shows_the_gap():
    df = run(levels=["none", "multiple", "almost-everything"], campaigns=4, per_campaign=6, background=15)
    f1 = df.pivot(index="rotation", columns="method", values="f1")
    assert f1.loc["none", "MailShark correlation"] >= 0.95
    assert f1.loc["multiple", "MailShark correlation"] > f1.loc["multiple", "IOC matching (baseline)"] + 0.3
    assert f1.loc["almost-everything", "MailShark correlation"] > 0.8 > f1.loc["almost-everything", "IOC matching (baseline)"]


def test_report_is_self_contained(tmp_path, corpus):
    _, manifest, ex = corpus
    msgs, _, _, sketches = to_frames(list(ex.values()))
    labels, _ = cluster_campaigns(msgs, sketches)
    path = build_report(tmp_path, msgs, manifest, trace_all(msgs, labels))
    text = path.read_text(encoding="utf-8")
    assert "Chain of custody" in text and "<script" not in text and "http://" not in text.split("<main>")[0]
    assert isinstance(pd.read_json(tmp_path / "campaigns.json"), pd.DataFrame)
