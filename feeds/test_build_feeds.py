"""The Python feed builder must hash and lay out bits exactly like engine/src/intel/bloom.ts."""

import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location("build_feeds", Path(__file__).with_name("build_feeds.py"))
bf = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bf)


def test_murmur3_matches_reference_vectors():
    # Same vectors as engine/test/unit.test.ts
    assert bf.murmur3_32("", 0) == 0
    assert bf.murmur3_32("hello", 0) == 613153351
    assert bf.murmur3_32("The quick brown fox jumps over the lazy dog", 0) == 0x2E4FF723
    assert bf.murmur3_32("", 1) == 0x514E28B7


def test_bloom_roundtrip_and_normalization():
    entries = {bf.normalize(h) for h in ["www.Evil-Login.example.", "phish.badsite.top", "docs.google.com", "10.0.0.1"]} - {None}
    assert "evil-login.example" in entries and "docs.google.com" not in entries
    bits, m, k = bf.bloom(entries)
    for e in entries:
        assert bf.contains(bits, m, k, e)
    assert not bf.contains(bits, m, k, "google.com")


def test_parse_hosts_format():
    assert bf.parse("# comment\n127.0.0.1\tbad.example\n127.0.0.1\twww.worse.example\n", "hosts") == {"bad.example", "worse.example"}


def test_popular_sites_are_dropped_but_tenant_pages_and_ips_are_kept():
    tranco = "\n".join(["1,google.com", "2,instagram.com", "3,weebly.com", "4,iol.ie", "5,example.org"])
    ranks = bf.parse_tranco(tranco, top=4)
    assert ranks == {"google.com": 1, "instagram.com": 2, "weebly.com": 3, "iol.ie": 4}
    tenants = {f"phish{i}.weebly.com" for i in range(bf.TENANT_MIN)}
    entries = {"iol.ie", "l.instagram.com", "evil-login.blogspot.com", "phish.example.net", "203.0.113.9"} | tenants
    kept = bf.drop_popular(entries, ranks)
    assert kept == {"evil-login.blogspot.com", "phish.example.net", "203.0.113.9"} | tenants
    # A lone subdomain of a top site is a brand host (redirector, CDN), not a tenant page.
    assert bf.drop_popular({"phish0.weebly.com"}, ranks) == set()
    assert bf.drop_popular({"phish0.weebly.com"}, ranks, universe=entries) == {"phish0.weebly.com"}
    assert bf.registrable("a.b.example.co.uk") == "example.co.uk"
