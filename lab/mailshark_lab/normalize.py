"""Normalisation into pandas tables.

Raw indicators are brought into comparable form so that per-recipient noise does not hide reuse:
registrable domains instead of hosts, URL *templates* instead of tokenised URLs, subject templates
instead of personalised subjects, MinHash sketches instead of full text.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from urllib.parse import parse_qsl, unquote, urlsplit

import pandas as pd
import tldextract
from datasketch import MinHash

from .extract import Extracted

# Offline Public Suffix List snapshot bundled with tldextract: no network calls.
_TLD = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)

NUM_PERM = 64


def registrable(host: str) -> str:
    host = (host or "").lower().strip(".").split(":")[0]
    if not host:
        return ""
    if re.fullmatch(r"[0-9.]+|[0-9a-f:]+", host):
        return host
    ext = _TLD(host)
    return f"{ext.domain}.{ext.suffix}" if ext.domain and ext.suffix else host


def domain_of(address: str) -> str:
    return address.rsplit("@", 1)[1].lower() if "@" in (address or "") else ""


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    return -sum(c / len(s) * math.log2(c / len(s)) for c in counts.values())


def _segment(seg: str) -> str:
    d = unquote(seg)
    if re.fullmatch(r"\d+", d):
        return "{n}"
    if re.fullmatch(r"[0-9a-f]{8,}", d, re.I):
        return "{hex}"
    if len(d) >= 24 or re.fullmatch(r"(?=.*\d)(?=.*[a-z])[a-z0-9_-]{12,}", d, re.I) or (len(d) >= 10 and _entropy(d) > 3.6):
        return "{tok}"
    if re.fullmatch(r"(?=(?:[^\d]*\d){2})(?=(?:[^a-z]*[a-z]){2})[a-z0-9_-]{5,}", d, re.I):
        return "{tok}"
    return re.sub(r"\d+", "{n}", d.lower())


def url_template(url: str) -> tuple[str, str, str]:
    """Return (registrable domain, full template, path-only template)."""
    try:
        u = urlsplit(url)
    except ValueError:
        return "", "", ""
    reg = registrable(u.hostname or "")
    segs = [_segment(s) for s in u.path.split("/") if s][:8]
    keys = sorted({k.lower() for k, _ in parse_qsl(u.query)})[:8]
    path = "/" + "/".join(segs) + ("?" + "&".join(keys) if keys else "")
    return reg, reg + path, path


def subject_template(subject: str) -> str:
    s = subject.lower()
    s = re.sub(r"https?://\S+", "{url}", s)
    s = re.sub(r"[\w.+-]+@[\w-]+\.[\w.-]+", "{email}", s)
    s = re.sub(r"\b\d{1,2}[/.-]\d{1,2}[/.-]\d{2,4}\b", "{date}", s)
    s = re.sub(r"\b(?=[a-z0-9]*\d)(?=[a-z0-9]*[a-z])[a-z0-9]{6,}\b", "{id}", s)
    s = re.sub(r"[#№]?\d[\d,.]*", "{n}", s)
    return " ".join(s.split())


def local_template(address: str) -> str:
    local = address.split("@", 1)[0].lower() if address else ""
    return re.sub(r"[a-z]{12,}", "{w}", re.sub(r"\d+", "{n}", local))


def msgid_template(message_id: str) -> str:
    m = re.search(r"<?([^<>@\s]+)@", message_id or "")
    if not m:
        return ""
    local = re.sub(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "{uuid}", m.group(1), flags=re.I)
    local = re.sub(r"[A-Za-z0-9+/_-]{16,}={0,2}", "{tok}", local)
    return re.sub(r"\d+", "{n}", local)


def minhash(text: str) -> MinHash:
    tokens = re.findall(r"[^\W_]{2,}", text.lower())[:6000]
    shingles = {" ".join(tokens[i: i + 3]) for i in range(max(1, len(tokens) - 2))} if tokens else set()
    mh = MinHash(num_perm=NUM_PERM, seed=7)
    for s in list(shingles)[:4000]:
        mh.update(s.encode("utf-8"))
    return mh


INTENTS = {
    "credential": ["verify your", "confirm your identity", "password", "sign in", "log in", "mailbox", "storage", "account has been limited", "credentials", "validate"],
    "payment": ["invoice", "payment", "billing", "bank details", "wire transfer", "overdue", "remittance", "settle"],
    "delivery": ["parcel", "package", "delivery", "customs fee", "shipment", "tracking"],
    "document": ["review and sign", "shared", "document", "files", "recording", "view the"],
    "crypto": ["wallet", "seed phrase", "crypto", "bitcoin", "token"],
}


def intent_of(text: str) -> str:
    """Coarse lure category from keyword evidence (the semantic invariant attackers rarely change)."""
    low = text.lower()
    scores = {k: sum(low.count(w) for w in words) for k, words in INTENTS.items()}
    best = max(scores, key=scores.get)
    return best if scores[best] >= 2 else ""


def net24(ip: str | None) -> str:
    if not ip:
        return ""
    if "." in ip:
        return ".".join(ip.split(".")[:3]) + ".0/24"
    parts = ip.split(":")
    return ":".join(parts[:3]) + "::/48"


def to_frames(items: list[Extracted]) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, dict[str, MinHash]]:
    """Build the message, URL and attachment tables plus MinHash sketches per message."""
    msgs, urls, atts = [], [], []
    sketches: dict[str, MinHash] = {}
    for e in items:
        dom = domain_of(e.from_addr)
        link_domains, templates, paths = set(), set(), set()
        for url, text in e.urls:
            reg, tpl, path = url_template(url)
            if not reg:
                continue
            urls.append({"msg_id": e.msg_id, "url": url, "anchor_text": text[:200], "domain": reg, "template": tpl, "path": path})
            if re.search(r"unsub|opt-?out|/un/", url, re.I):
                continue
            link_domains.add(reg)
            templates.add(tpl)
            if path.count("/") >= 2:
                paths.add(path)
        for a in e.attachments:
            atts.append({"msg_id": e.msg_id, **{k: v for k, v in a.__dict__.items() if k != "zip_entries"}, "zip_entries": "|".join(a.zip_entries[:50])})
        msgs.append(
            {
                "msg_id": e.msg_id,
                "date": pd.to_datetime(e.date, unit="s", utc=True) if e.date else pd.NaT,
                "subject": e.subject,
                "subject_template": subject_template(e.subject),
                "from_name": e.from_name,
                "from_addr": e.from_addr,
                "from_domain": registrable(dom),
                "local_template": local_template(e.from_addr),
                "reply_to_domain": registrable(domain_of(e.reply_to)),
                "return_path_domain": registrable(domain_of(e.return_path)),
                "origin_ip": e.origin_ip or "",
                "origin_net": net24(e.origin_ip),
                "origin_host_domain": registrable(e.origin_host or ""),
                "x_mailer": re.sub(r"\d+(\.\d+)*", "{v}", e.x_mailer.lower())[:80],
                "header_order": e.header_order,
                "msgid_template": msgid_template(e.message_id),
                "dkim_domain": e.auth.get("dkim_d", ""),
                "dkim_selectors": ",".join(sorted({re.sub(r"\d+", "{n}", s) for s in e.dkim_selectors})),
                "spf": e.auth.get("spf", ""),
                "dkim": e.auth.get("dkim", ""),
                "dmarc": e.auth.get("dmarc", ""),
                "verp_campaign": e.verp_campaign or "",
                "html_skeleton": e.html_skeleton,
                "forms": e.forms,
                "password_inputs": e.password_inputs,
                "n_urls": len(e.urls),
                "n_attachments": len(e.attachments),
                "link_domains": sorted(link_domains),
                "url_templates": sorted(templates),
                "url_paths": sorted(paths),
                "attachment_sha256": sorted({a.sha256 for a in e.attachments}),
                "attachment_structs": sorted({f"{a.detected}|{a.filename.rsplit('.', 1)[-1].lower()}|{'|'.join(sorted(re.sub(r'[0-9]+', '#', x) for x in a.zip_entries))[:200]}" for a in e.attachments}),
                "attachment_ssdeep": [a.ssdeep for a in e.attachments if a.ssdeep],
                "text_preview": e.text[:300],
                "intent": intent_of(f"{e.subject} {e.text[:5000]}"),
                "brand": re.sub(r"[^a-z0-9]+", " ", e.from_name.lower()).strip(),
            }
        )
        sketches[e.msg_id] = minhash(f"{e.subject} {e.text[:20000]}")
    return pd.DataFrame(msgs), pd.DataFrame(urls), pd.DataFrame(atts), sketches
