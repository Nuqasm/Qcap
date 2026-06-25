"""RFC 8785 JSON Canonicalization Scheme (JCS) for hashing and signing."""

from __future__ import annotations

import json
import math
from typing import Any


def canon(obj: Any) -> bytes:
    """Return canonical UTF-8 bytes for a JSON-serializable object."""
    return _serialize(obj).encode("utf-8")


def _serialize(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return _serialize_number(value)
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, list):
        return "[" + ",".join(_serialize(item) for item in value) + "]"
    if isinstance(value, dict):
        keys = sorted(value.keys())
        parts = [json.dumps(key, ensure_ascii=False) + ":" + _serialize(value[key]) for key in keys]
        return "{" + ",".join(parts) + "}"
    raise TypeError(f"unsupported JSON type: {type(value)!r}")


def _serialize_number(value: float) -> str:
    if not math.isfinite(value):
        raise ValueError("non-finite numbers are not allowed in canonical JSON")
    if value == 0.0 and math.copysign(1.0, value) < 0:
        return "-0"
    if value == int(value) and abs(value) < 1e21:
        return str(int(value))
    text = format(value, ".15g")
    if "e" in text or "E" in text:
        return text
    if "." not in text:
        return text + ".0"
    return text.rstrip("0").rstrip(".") if "." in text else text
