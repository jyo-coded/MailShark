"""Indicator extraction: headers, delivery route, authentication, URLs and attachment hashes.

Uses only the Python standard library for parsing (``email``, ``html.parser``) and ``hashlib`` for
evidence hashing. Nothing is rendered, executed or fetched.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import dataclass, field
from email import policy
from email.header import decode_header, make_header
from email.message import Message
from email.parser import BytesParser
from email.utils import getaddresses, parsedate_to_datetime
from html.parser import HTMLParser
from typing import Any

try:  # fuzzy hashing is optional; the lab degrades gracefully without it
    import ppdeep
except ImportError:  # pragma: no cover
    ppdeep = None

URL_RE = re.compile(r"""\b(?:https?://|www\.)[^\s<>"'`{}|\\^\[\]]+""", re.I)
IP_BRACKET_RE = re.compile(r"\[(?:IPv6:)?([0-9a-fA-F:.]+)\]")
TRAILING = ".,;:!?)]}'\"’”>"


def decode(value: Any) -> str:
    if value is None:
        return ""
    try:
        return str(make_header(decode_header(str(value)))).strip()
    except Exception:  # noqa: BLE001 - malformed encoded-words
        return str(value).strip()


def _is_public_ip(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (a.is_private or a.is_loopback or a.is_link_local or a.is_multicast or a.is_reserved or a.is_unspecified)


# ── HTML ───────────────────────────────────────────────────────────────────────


class _HtmlScan(HTMLParser):
    """Inert HTML walk: visible text, anchors, tag skeleton, forms."""

    SKIP = {"script", "style", "head", "title", "noscript"}
    SKELETON = {"table", "tr", "td", "div", "p", "a", "img", "span", "h1", "h2", "h3", "ul", "li", "form", "input", "button"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.text: list[str] = []
        self.anchors: list[tuple[str, str]] = []
        self.skeleton: list[str] = []
        self.forms = 0
        self.password_inputs = 0
        self._skip = 0
        self._depth = 0
        self._anchor: list[str] | None = None
        self._href = ""

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k: v or "" for k, v in attrs}
        self._depth += 1
        if tag in self.SKELETON and len(self.skeleton) < 4000:
            self.skeleton.append(f"{min(self._depth, 14)}{tag}")
        if tag in self.SKIP:
            self._skip += 1
        elif tag == "a" and a.get("href"):
            self._anchor, self._href = [], a["href"]
        elif tag == "form":
            self.forms += 1
        elif tag == "input" and a.get("type", "").lower() == "password":
            self.password_inputs += 1
        elif tag in {"br", "p", "div", "tr", "li"}:
            self.text.append("\n")

    def handle_endtag(self, tag: str) -> None:
        self._depth = max(0, self._depth - 1)
        if tag in self.SKIP and self._skip:
            self._skip -= 1
        elif tag == "a" and self._anchor is not None:
            self.anchors.append((self._href, " ".join("".join(self._anchor).split())))
            self._anchor = None

    def handle_data(self, data: str) -> None:
        if self._skip:
            return
        self.text.append(data)
        if self._anchor is not None:
            self._anchor.append(data)


# ── Received chain ─────────────────────────────────────────────────────────────


@dataclass
class Hop:
    raw: str
    from_host: str | None
    from_ip: str | None
    by_host: str | None
    timestamp: float | None


def parse_received(value: str) -> Hop:
    v = " ".join(value.split())
    main, _, date = v.rpartition(";") if ";" in v else (v, "", "")
    from_m = re.search(r"\bfrom\s+([^\s;()]+)", main, re.I)
    by_m = re.search(r"\bby\s+([^\s;()]+)", main, re.I)
    from_clause = main[from_m.start(): by_m.start()] if from_m and by_m and by_m.start() > from_m.start() else (main[from_m.start():] if from_m else "")
    ips = [m for m in IP_BRACKET_RE.findall(from_clause) if re.match(r"^[0-9a-f:.]+$", m, re.I)]
    rdns = re.search(r"\(\s*([a-z0-9][a-z0-9.-]*\.[a-z]{2,})\.?\s", from_clause + " ", re.I)
    ts = None
    try:
        ts = parsedate_to_datetime(re.sub(r"\([^)]*\)", "", date).strip()).timestamp() if date.strip() else None
    except (TypeError, ValueError, IndexError):
        ts = None
    host = (rdns.group(1) if rdns else (from_m.group(1) if from_m else None)) or None
    return Hop(v, host.lower().rstrip(".") if host else None, ips[-1] if ips else None, by_m.group(1).lower().rstrip(".") if by_m else None, ts)


def origin_of(hops: list[Hop]) -> tuple[str | None, str | None]:
    """First hop (newest→oldest) received from an external public IP: the true connecting client."""
    for hop in hops:
        if hop.from_ip and _is_public_ip(hop.from_ip):
            return hop.from_ip, hop.from_host
    return None, None


# ── Authentication-Results ─────────────────────────────────────────────────────


def parse_auth_results(value: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for clause in re.split(r";(?![^()]*\))", " ".join(value.split())):
        m = re.match(r"\s*(spf|dkim|dmarc|arc|compauth)\s*=\s*([a-z]+)", clause, re.I)
        if not m:
            continue
        method, result = m.group(1).lower(), m.group(2).lower()
        if method == "dkim" and out.get("dkim") == "pass":
            continue
        out.setdefault(method, result)
        if method == "dkim" and result == "pass":
            out["dkim"] = "pass"
            d = re.search(r"header\.(?:d|i)=@?([^\s;]+)", clause)
            if d:
                out.setdefault("dkim_d", d.group(1).lower())
        if method == "spf":
            mf = re.search(r"smtp\.mailfrom=([^\s;]+)", clause)
            if mf:
                out["spf_mailfrom"] = mf.group(1).strip('"').lower()
    return out


# ── Attachments ────────────────────────────────────────────────────────────────

MAGIC = [
    (b"%PDF-", "pdf"), (b"PK\x03\x04", "zip"), (b"\xd0\xcf\x11\xe0", "ole"), (b"MZ", "pe"), (b"\x7fELF", "elf"), (b"Rar!", "rar"),
    (b"7z\xbc\xaf", "7z"), (b"\x1f\x8b", "gzip"), (b"\x89PNG", "png"), (b"\xff\xd8\xff", "jpeg"), (b"GIF8", "gif"), (b"{\\rtf", "rtf"),
    (b"L\x00\x00\x00\x01\x14\x02\x00", "lnk"),
]


def sniff(data: bytes) -> str:
    for sig, kind in MAGIC:
        if data.startswith(sig):
            return kind
    head = data[:600].lstrip().lower()
    if head.startswith((b"<!doctype html", b"<html", b"<head", b"<body", b"<script", b"<form")):
        return "html"
    if b"<svg" in head:
        return "svg"
    return "text" if data and sum(32 <= b < 127 or b in (9, 10, 13) for b in data[:512]) / min(len(data), 512) > 0.95 else "binary"


@dataclass
class Attachment:
    filename: str
    content_type: str
    size: int
    md5: str
    sha1: str
    sha256: str
    ssdeep: str | None
    detected: str
    zip_entries: list[str] = field(default_factory=list)


def hash_attachment(filename: str, content_type: str, data: bytes) -> Attachment:
    entries: list[str] = []
    kind = sniff(data)
    if kind == "zip":
        import io
        import zipfile

        try:
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                entries = [i.filename for i in z.infolist()[:200]]
        except zipfile.BadZipFile:
            entries = []
    return Attachment(
        filename=filename,
        content_type=content_type,
        size=len(data),
        md5=hashlib.md5(data).hexdigest(),  # noqa: S324 - IOC format, not security
        sha1=hashlib.sha1(data).hexdigest(),  # noqa: S324
        sha256=hashlib.sha256(data).hexdigest(),
        ssdeep=ppdeep.hash(data) if ppdeep and len(data) >= 64 else None,
        detected=kind,
        zip_entries=entries,
    )


# ── Message ────────────────────────────────────────────────────────────────────

TRANSIT = re.compile(r"^(received|x-received|arc-|authentication-results|received-spf|delivered-to|return-path|x-google-|x-gm-|x-ms-|x-microsoft-|x-forefront-|x-spam|x-virus)", re.I)


@dataclass
class Extracted:
    msg_id: str
    subject: str = ""
    from_name: str = ""
    from_addr: str = ""
    reply_to: str = ""
    return_path: str = ""
    to: str = ""
    message_id: str = ""
    date: float | None = None
    x_mailer: str = ""
    header_order: str = ""
    origin_ip: str | None = None
    origin_host: str | None = None
    hops: int = 0
    auth: dict[str, str] = field(default_factory=dict)
    dkim_selectors: list[str] = field(default_factory=list)
    list_unsubscribe: bool = False
    verp_campaign: str | None = None
    text: str = ""
    html_skeleton: str = ""
    forms: int = 0
    password_inputs: int = 0
    urls: list[tuple[str, str]] = field(default_factory=list)  # (url, anchor text)
    attachments: list[Attachment] = field(default_factory=list)


def _parse(raw: bytes) -> Message:
    try:
        return BytesParser(policy=policy.default).parsebytes(raw)
    except Exception:  # noqa: BLE001 - fall back to the lenient legacy policy
        return BytesParser(policy=policy.compat32).parsebytes(raw)


def _payload_text(part: Message) -> str:
    try:
        payload = part.get_payload(decode=True)
    except Exception:  # noqa: BLE001
        return ""
    if not isinstance(payload, (bytes, bytearray)):
        return ""
    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, errors="replace")
    except LookupError:
        return payload.decode("utf-8", errors="replace")


def extract(msg_id: str, raw: bytes) -> Extracted:
    msg = _parse(raw)
    e = Extracted(msg_id=msg_id)
    headers = list(msg.items())
    e.subject = decode(msg.get("Subject"))
    frm = getaddresses([decode(msg.get("From"))])
    if frm:
        e.from_name, e.from_addr = frm[0][0].strip(), frm[0][1].strip().lower()
    rt = getaddresses([decode(msg.get("Reply-To"))])
    e.reply_to = rt[0][1].lower() if rt and rt[0][1] else ""
    e.return_path = decode(msg.get("Return-Path")).strip("<>").lower()
    e.to = decode(msg.get("Delivered-To") or msg.get("To"))
    e.message_id = decode(msg.get("Message-ID"))
    try:
        e.date = parsedate_to_datetime(decode(msg.get("Date"))).timestamp() if msg.get("Date") else None
    except (TypeError, ValueError, IndexError):
        e.date = None
    e.x_mailer = decode(msg.get("X-Mailer") or msg.get("User-Agent"))
    e.header_order = hashlib.sha1(">".join(k.lower() for k, _ in headers if not TRANSIT.match(k)).encode()).hexdigest()[:16]  # noqa: S324

    hops = [parse_received(str(v)) for v in msg.get_all("Received", [])]
    e.hops = len(hops)
    e.origin_ip, e.origin_host = origin_of(hops)
    if e.date is None:
        stamps = [h.timestamp for h in hops if h.timestamp]
        e.date = min(stamps) if stamps else None
    ar = msg.get_all("Authentication-Results", [])
    e.auth = parse_auth_results(str(ar[0])) if ar else {}
    for sig in msg.get_all("DKIM-Signature", []):
        s = re.search(r"\bs=([^;\s]+)", str(sig))
        if s:
            e.dkim_selectors.append(s.group(1).lower())
    e.list_unsubscribe = msg.get("List-Unsubscribe") is not None
    verp = re.search(r"(?:cli|client|cust|c)[._-]?(\d{3,})[-._](\d{4,})", e.return_path or e.auth.get("spf_mailfrom", ""))
    e.verp_campaign = f"{verp.group(1)}:{verp.group(2)}" if verp else None

    plain: list[str] = []
    html_parts: list[str] = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        ctype = part.get_content_type()
        disp = (part.get_content_disposition() or "").lower()
        fname = part.get_filename()
        if fname or disp == "attachment" or (not ctype.startswith("text/") and ctype != "message/rfc822"):
            try:
                data = part.get_payload(decode=True) or b""
            except Exception:  # noqa: BLE001
                data = b""
            if isinstance(data, (bytes, bytearray)) and data:
                e.attachments.append(hash_attachment(decode(fname) or "unnamed", ctype, bytes(data)))
            continue
        if ctype == "text/html":
            html_parts.append(_payload_text(part))
        elif ctype == "text/plain":
            plain.append(_payload_text(part))

    if html_parts:
        scan = _HtmlScan()
        try:
            scan.feed("\n".join(html_parts)[:2_000_000])
        except Exception:  # noqa: BLE001 - malformed HTML
            pass
        e.text = " ".join("".join(scan.text).split())
        e.html_skeleton = hashlib.sha1(",".join(scan.skeleton).encode()).hexdigest()[:16] if len(scan.skeleton) >= 5 else ""  # noqa: S324
        e.forms, e.password_inputs = scan.forms, scan.password_inputs
        e.urls.extend((u.strip(), t) for u, t in scan.anchors if u.lower().startswith(("http:", "https:")))
    if not e.text:
        e.text = " ".join("\n".join(plain).split())
    for m in URL_RE.finditer("\n".join(plain)[:200_000]):
        u = m.group(0).rstrip(TRAILING)
        e.urls.append(("http://" + u if u.lower().startswith("www.") else u, ""))
    return e
