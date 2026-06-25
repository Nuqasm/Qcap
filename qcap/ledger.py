"""Hash-chained append-only JSONL ledger."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from qcap.canon import canon
from qcap.capsule import read_signed_over
from qcap.hashing import hash_bytes

GENESIS_PREV_HASH = "sha256:" + ("0" * 64)
DEFAULT_LEDGER = Path("qcap.ledger.jsonl")


class LedgerError(Exception):
    """Ledger operation failed."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _load_entries(path: Path) -> list[dict]:
    if not path.exists():
        return []
    entries: list[dict] = []
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError as exc:
            raise LedgerError(f"invalid JSON on line {line_no}") from exc
        if not isinstance(entry, dict):
            raise LedgerError(f"ledger line {line_no} is not a JSON object")
        entries.append(entry)
    return entries


def _entry_hash(entry_without_hash: dict) -> str:
    return hash_bytes(canon(entry_without_hash))


def add_entry(*, ledger_path: Path, capsule_path: Path) -> dict:
    capsule_path = capsule_path.resolve()
    if not capsule_path.is_file():
        raise LedgerError(f"capsule not found: {capsule_path}")

    signed_over = read_signed_over(capsule_path)
    entries = _load_entries(ledger_path)
    prev_hash = entries[-1]["entry_hash"] if entries else GENESIS_PREV_HASH
    seq = len(entries) + 1

    body = {
        "seq": seq,
        "ts": _utc_now(),
        "capsule_id": signed_over,
        "prev_hash": prev_hash,
    }
    entry = dict(body)
    entry["entry_hash"] = _entry_hash(body)

    ledger_path.parent.mkdir(parents=True, exist_ok=True)
    with ledger_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, separators=(",", ":")) + "\n")

    return entry


def verify_ledger(ledger_path: Path) -> int:
    entries = _load_entries(ledger_path)
    if not entries:
        raise LedgerError("ledger is empty")

    expected_prev = GENESIS_PREV_HASH
    for index, entry in enumerate(entries, start=1):
        seq = entry.get("seq")
        if seq != index:
            raise LedgerError(f"sequence break at entry {index}: expected seq={index}, got {seq!r}")

        prev_hash = entry.get("prev_hash")
        if prev_hash != expected_prev:
            raise LedgerError(f"chain break at entry {index}: prev_hash does not match previous entry")

        stored_hash = entry.get("entry_hash")
        body = {key: value for key, value in entry.items() if key != "entry_hash"}
        recomputed = _entry_hash(body)
        if stored_hash != recomputed:
            raise LedgerError(f"entry hash mismatch at entry {index} (ledger has been modified)")

        expected_prev = stored_hash

    return len(entries)
