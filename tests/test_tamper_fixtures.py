"""Conformance tests for tamper-marked fixtures (SPEC §11)."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from qcap.capsule import VerificationError, verify_capsule

ROOT = Path(__file__).resolve().parents[1]
TAMPER_DIR = ROOT / "tests" / "tamper"
INDEX_PATH = TAMPER_DIR / "index.json"
WEIGHTS = ROOT / "examples" / "model_custody" / "weights.stub"
BUILD_SCRIPT = TAMPER_DIR / "build_fixtures.py"


def _ensure_fixtures() -> None:
    if INDEX_PATH.exists():
        index = json.loads(INDEX_PATH.read_text(encoding="utf-8"))
        if all((TAMPER_DIR / item["file"]).exists() for item in index["fixtures"]):
            return
    subprocess.run([sys.executable, str(BUILD_SCRIPT)], check=True, cwd=ROOT)


def _load_index() -> dict:
    _ensure_fixtures()
    return json.loads(INDEX_PATH.read_text(encoding="utf-8"))


def test_tamper_fixtures_index_is_present() -> None:
    index = _load_index()
    assert len(index["fixtures"]) >= 4


def test_valid_fixture_passes() -> None:
    entry = next(item for item in _load_index()["fixtures"] if not item["tamper"])
    result = verify_capsule(
        TAMPER_DIR / entry["file"],
        referenced_payloads={WEIGHTS.name: WEIGHTS},
    )
    assert result.signer_id == "alice"


@pytest.mark.parametrize(
    "filename",
    ["tamper-append-byte.qcap", "tamper-payload.qcap", "tamper-record.qcap"],
)
def test_tamper_marked_fixtures_fail(filename: str) -> None:
    capsule = TAMPER_DIR / filename
    assert capsule.is_file(), "run tests/tamper/build_fixtures.py"
    with pytest.raises(VerificationError):
        verify_capsule(capsule)
