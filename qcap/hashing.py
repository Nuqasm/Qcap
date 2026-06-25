"""Content hashing helpers."""

from __future__ import annotations

import hashlib
from pathlib import Path

from qcap.canon import canon


def hash_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def hash_file(path: Path) -> str:
    return hash_bytes(path.read_bytes())


def hash_canonical(obj: object) -> str:
    return hash_bytes(canon(obj))
