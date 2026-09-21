"""Evidence acquisition with chain of custody.

Every source file and every individual message is hashed (SHA-256) at intake so any later
report can prove it analysed exactly the bytes that were collected. Originals are never modified.
"""

from __future__ import annotations

import hashlib
import mailbox
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Iterator

import pandas as pd


@dataclass(frozen=True)
class Evidence:
    msg_id: str  # SHA-256 of the raw message bytes
    source: str  # file path, plus "#n" for the n-th message of an mbox
    raw: bytes
    acquired_at: str

    @property
    def size(self) -> int:
        return len(self.raw)


def sha256_file(path: Path, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while block := fh.read(chunk):
            h.update(block)
    return h.hexdigest()


def _looks_like_mbox(path: Path) -> bool:
    if path.suffix.lower() in {".mbox", ".mbx"}:
        return True
    try:
        with path.open("rb") as fh:
            return fh.read(5) == b"From "
    except OSError:
        return False


def _iter_files(paths: Iterable[Path]) -> Iterator[Path]:
    for p in paths:
        if p.is_dir():
            for child in sorted(p.rglob("*")):
                if child.is_file() and not child.name.startswith(".") and child.name != "cmds":
                    yield child
        elif p.is_file():
            yield p


def _iter_messages(path: Path) -> Iterator[tuple[str, bytes]]:
    if _looks_like_mbox(path):
        box = mailbox.mbox(str(path), create=False)
        try:
            for i, key in enumerate(box.iterkeys(), start=1):
                yield f"{path}#{i}", box.get_bytes(key)
        finally:
            box.close()
    else:
        data = path.read_bytes()
        if data.startswith(b"From "):  # single message saved with an mbox envelope line
            data = data.split(b"\n", 1)[1] if b"\n" in data else b""
        yield str(path), data


def acquire(paths: Iterable[str | Path], limit: int | None = None) -> tuple[list[Evidence], pd.DataFrame]:
    """Collect messages from .eml files, directories and mbox archives.

    Returns the evidence items and a chain-of-custody manifest (one row per message, with the
    SHA-256 of both the message and the container file it came from).
    """
    items: list[Evidence] = []
    rows: list[dict] = []
    seen: set[str] = set()
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    for f in _iter_files(Path(p) for p in paths):
        try:
            container_hash = sha256_file(f)
            for source, raw in _iter_messages(f):
                if not raw.strip():
                    continue
                digest = hashlib.sha256(raw).hexdigest()
                duplicate = digest in seen
                rows.append(
                    {
                        "msg_id": digest,
                        "source": source,
                        "container": str(f),
                        "container_sha256": container_hash,
                        "size": len(raw),
                        "md5": hashlib.md5(raw).hexdigest(),  # noqa: S324 - forensic identifier, not security
                        "sha1": hashlib.sha1(raw).hexdigest(),  # noqa: S324
                        "duplicate": duplicate,
                        "acquired_at": now,
                    }
                )
                if duplicate:
                    continue
                seen.add(digest)
                items.append(Evidence(digest, source, raw, now))
                if limit and len(items) >= limit:
                    return items, pd.DataFrame(rows)
        except (OSError, mailbox.Error) as exc:  # unreadable/quarantined file: recorded, not fatal
            rows.append({"msg_id": None, "source": str(f), "container": str(f), "error": str(exc), "acquired_at": now})
    return items, pd.DataFrame(rows)
