"""Compile public threat feeds into Bloom filters for the MailShark extension.

The extension downloads these filters and checks domains *locally*, so no domain from a user's mail
is ever sent to a server. Bit layout and hashing mirror engine/src/intel/bloom.ts exactly:

    h1 = murmur3_32(value, 0x9747b28c); h2 = murmur3_32(value, 0x5bd1e995) | 1
    bit_i = (h1 + i * h2) mod m        for i in 0..k-1, little-endian bit order inside each byte

Popular sites are filtered out before compiling, using the Tranco ranking. Community lists
regularly contain compromised-but-legitimate sites, ISPs and brand redirectors, and one bad page there
must not flag every email that mentions the site:

  * a bare popular domain (iol.ie, angelfire.com) is dropped;
  * a subdomain of a top brand site (l.instagram.com) is dropped, unless that site is evidently a
    hosting platform whose subdomains are customer pages (many listed tenants, e.g. evil.weebly.com).

The extension matches a feed entry against the exact host and its parents, never siblings, so a
listed tenant page never flags the platform itself.

    pip install tldextract
    python feeds/build_feeds.py --out feeds-out
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import math
import re
import sys
import urllib.request
import zipfile
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path

import tldextract

SEED_1 = 0x9747B28C
SEED_2 = 0x5BD1E995
FALSE_POSITIVE_RATE = 1e-6

SOURCES = [
    {
        "name": "phishing-database",
        "url": "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-domains-ACTIVE.txt",
        "format": "domains",
        "license": "MIT, Phishing.Database (Mitchell Krog et al.)",
    },
    {
        "name": "urlhaus",
        "url": "https://urlhaus.abuse.ch/downloads/hostfile/",
        "format": "hosts",
        "license": "abuse.ch URLhaus terms of use (https://urlhaus.abuse.ch/api/)",
    },
]

# Multi-tenant platforms: one abusive page there must never blacklist the whole service. Specific
# subdomains of free-hosting platforms (evil.web.app) are kept; the bare service hosts are dropped.
NEVER_LIST = {
    "google.com", "docs.google.com", "drive.google.com", "sites.google.com", "forms.gle", "goo.gl", "storage.googleapis.com",
    "firebasestorage.googleapis.com", "googleusercontent.com", "microsoft.com", "live.com", "onedrive.live.com", "1drv.ms",
    "sharepoint.com", "office.com", "microsoftonline.com", "outlook.com", "dropbox.com", "dl.dropboxusercontent.com", "box.com",
    "github.com", "github.io", "raw.githubusercontent.com", "gitlab.com", "bit.ly", "t.co", "tinyurl.com", "linktr.ee", "canva.com",
    "wetransfer.com", "we.tl", "mediafire.com", "amazonaws.com", "s3.amazonaws.com", "cloudfront.net", "azurewebsites.net",
    "blob.core.windows.net", "web.app", "firebaseapp.com", "pages.dev", "workers.dev", "netlify.app", "vercel.app", "herokuapp.com",
    "weebly.com", "wixsite.com", "blogspot.com", "wordpress.com", "notion.site", "000webhostapp.com", "ipfs.io", "cloudflare-ipfs.com",
    "facebook.com", "instagram.com", "whatsapp.com", "linkedin.com", "twitter.com", "x.com", "youtube.com", "apple.com", "icloud.com",
    "paypal.com", "amazon.com", "yahoo.com", "gmail.com", "hotmail.com", "zoom.us", "adobe.com", "docusign.net", "salesforce.com",
    "godaddysites.com", "jimdosite.com", "webflow.io", "glitch.me", "repl.co", "ngrok.io", "trycloudflare.com", "duckdns.org",
}

TRANCO_URL = "https://tranco-list.eu/top-1m.csv.zip"
TRANCO_TOP = 100_000  # bare domains ranked this high are never listed
BRAND_TOP = 1_000  # subdomains of sites ranked this high are dropped...
TENANT_MIN = 10  # ...unless the site has at least this many listed subdomains (a hosting platform)

_psl = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=True)

HOST_RE = re.compile(r"^(?=.{3,253}$)[a-z0-9_](?:[a-z0-9_-]{0,62}[a-z0-9_])?(?:\.[a-z0-9_](?:[a-z0-9_-]{0,62}[a-z0-9_])?)+$")


def murmur3_32(value: str, seed: int = 0) -> int:
    data = value.encode("utf-8")
    c1, c2 = 0xCC9E2D51, 0x1B873593
    h = seed & 0xFFFFFFFF
    nblocks = len(data) // 4
    for i in range(nblocks):
        k = int.from_bytes(data[i * 4: i * 4 + 4], "little")
        k = (k * c1) & 0xFFFFFFFF
        k = ((k << 15) | (k >> 17)) & 0xFFFFFFFF
        k = (k * c2) & 0xFFFFFFFF
        h ^= k
        h = ((h << 13) | (h >> 19)) & 0xFFFFFFFF
        h = (h * 5 + 0xE6546B64) & 0xFFFFFFFF
    tail = data[nblocks * 4:]
    k1 = 0
    if len(tail) >= 3:
        k1 ^= tail[2] << 16
    if len(tail) >= 2:
        k1 ^= tail[1] << 8
    if tail:
        k1 ^= tail[0]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h ^= k1
    h ^= len(data)
    h ^= h >> 16
    h = (h * 0x85EBCA6B) & 0xFFFFFFFF
    h ^= h >> 13
    h = (h * 0xC2B2AE35) & 0xFFFFFFFF
    h ^= h >> 16
    return h


def normalize(host: str) -> str | None:
    h = host.strip().lower().rstrip(".")
    h = h[4:] if h.startswith("www.") else h
    if not h or h.startswith("#"):
        return None
    try:
        ipaddress.ip_address(h)
        return h
    except ValueError:
        pass
    if not HOST_RE.match(h) or h in NEVER_LIST:
        return None
    return h


def parse(text: str, fmt: str) -> set[str]:
    out: set[str] = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        host = line.split()[-1] if fmt == "hosts" else line.split()[0]
        n = normalize(host)
        if n:
            out.add(n)
    return out


def registrable(host: str) -> str:
    """Registrable domain using the Public Suffix List, private section included."""
    ext = _psl(host)
    return ext.top_domain_under_public_suffix or host


def parse_tranco(text: str, top: int = TRANCO_TOP) -> dict[str, int]:
    """Domain -> rank for the top `top` rows of a Tranco CSV."""
    out: dict[str, int] = {}
    for line in text.splitlines():
        rank, _, domain = line.strip().partition(",")
        if not domain or not rank.isdigit():
            continue
        if int(rank) > top:
            break
        out[domain.lower()] = int(rank)
    return out


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def drop_popular(entries: set[str], ranks: dict[str, int], universe: set[str] | None = None) -> set[str]:
    """Apply the popular-site rules above. `universe` (all sources combined) sizes the tenant counts."""
    tenants: dict[str, int] = {}
    for e in universe if universe is not None else entries:
        if not _is_ip(e):
            reg = registrable(e)
            if reg != e:
                tenants[reg] = tenants.get(reg, 0) + 1
    kept = set()
    for e in entries:
        if _is_ip(e):
            kept.add(e)
            continue
        reg = registrable(e)
        rank = ranks.get(reg)
        if rank is None:
            kept.add(e)
        elif e == reg:
            continue
        elif rank <= BRAND_TOP and tenants.get(reg, 0) < TENANT_MIN:
            continue
        else:
            kept.add(e)
    return kept


def bloom(entries: set[str], p: float = FALSE_POSITIVE_RATE) -> tuple[bytes, int, int]:
    n = max(1, len(entries))
    m = int(math.ceil(-n * math.log(p) / (math.log(2) ** 2)))
    m = (m + 7) // 8 * 8
    k = max(1, min(32, round(m / n * math.log(2))))
    bits = bytearray(m // 8)
    for e in entries:
        h1 = murmur3_32(e, SEED_1)
        h2 = murmur3_32(e, SEED_2) | 1
        for i in range(k):
            idx = (h1 + i * h2) % m
            bits[idx >> 3] |= 1 << (idx & 7)
    return bytes(bits), m, k


def contains(bits: bytes, m: int, k: int, value: str) -> bool:
    h1, h2 = murmur3_32(value, SEED_1), murmur3_32(value, SEED_2) | 1
    return all(bits[(idx := (h1 + i * h2) % m) >> 3] & (1 << (idx & 7)) for i in range(k))


def fetch_bytes(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "MailShark-feed-builder/1.0 (+https://github.com/jyo-coded/MailShark)"})
    with urllib.request.urlopen(req, timeout=180) as resp:  # noqa: S310 - fixed https sources
        return resp.read()


def fetch(url: str) -> str:
    return fetch_bytes(url).decode("utf-8", errors="replace")


def fetch_tranco(top: int) -> dict[str, int]:
    with zipfile.ZipFile(BytesIO(fetch_bytes(TRANCO_URL))) as zf:
        name = next(n for n in zf.namelist() if n.endswith(".csv"))
        return parse_tranco(zf.read(name).decode("utf-8", errors="replace"), top)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="feeds-out")
    ap.add_argument("--allowlist-top", type=int, default=TRANCO_TOP, help="drop entries under the Tranco top-N sites")
    args = ap.parse_args(argv)
    out = Path(args.out) / "v1"
    out.mkdir(parents=True, exist_ok=True)
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    # Publishing without the allowlist would ship known false positives, so its failure is fatal.
    popular = fetch_tranco(args.allowlist_top)
    if len(popular) < args.allowlist_top * 0.9:
        print(f"[feeds] allowlist too small ({len(popular):,})", file=sys.stderr)
        return 1
    print(f"[feeds] allowlist: Tranco top {len(popular):,}")
    fetched: list[tuple[dict, set[str]]] = []
    for src in SOURCES:
        try:
            fetched.append((src, parse(fetch(src["url"]), src["format"])))
        except Exception as exc:  # noqa: BLE001 - a failing source must not block the others
            print(f"[feeds] {src['name']}: skipped ({exc})", file=sys.stderr)
    universe = set().union(*(raw for _, raw in fetched)) if fetched else set()
    lists = []
    for src, raw in fetched:
        entries = drop_popular(raw, popular, universe)
        print(f"[feeds] {src['name']}: {len(raw) - len(entries):,} popular-site entries dropped")
        if not entries:
            print(f"[feeds] {src['name']}: no entries", file=sys.stderr)
            continue
        bits, m, k = bloom(entries)
        file = f"{src['name']}.bloom"
        (out / file).write_bytes(bits)
        sample = next(iter(entries))
        assert contains(bits, m, k, sample), "bloom self-check failed"
        lists.append({"name": src["name"], "file": file, "m": m, "k": k, "count": len(entries), "sha256": hashlib.sha256(bits).hexdigest(), "updated": now, "source": src["url"], "license": src["license"]})
        print(f"[feeds] {src['name']}: {len(entries):,} hosts -> {len(bits) / 1024:.0f} KiB (k={k})")
    if not lists:
        print("[feeds] no feed could be built", file=sys.stderr)
        return 1
    (out / "manifest.json").write_text(json.dumps({"version": 1, "generated": now, "allowlist": f"Tranco top {args.allowlist_top} (https://tranco-list.eu)", "lists": lists}, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
