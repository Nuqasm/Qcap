"""Roundtrip and tamper tests for qcap."""

from __future__ import annotations

import json
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from qcap.canon import canon
from qcap.capsule import VerificationError, seal_capsule, verify_capsule
from qcap.hashing import hash_bytes
from qcap.ledger import LedgerError, add_entry, verify_ledger
from qcap.sign import resolve_algorithm

ROOT = Path(__file__).resolve().parents[1]
MODELCARD = ROOT / "examples" / "model_custody" / "modelcard.json"
RUN_RECORD = ROOT / "examples" / "exec_receipt" / "run_record.json"


def test_canonical_json_is_stable() -> None:
    obj = {"b": 2, "a": 1, "nested": {"z": True, "y": None}}
    assert canon(obj) == b'{"a":1,"b":2,"nested":{"y":null,"z":true}}'


def test_seal_and_verify_model_custody(tmp_path: Path) -> None:
    out = tmp_path / "test.qcap"
    algo, subject = seal_capsule(
        payload_paths=[MODELCARD],
        out_path=out,
        signer="alice",
        algorithm=resolve_algorithm("ed25519"),
    )
    assert subject == "model"
    assert algo == "Ed25519"

    result = verify_capsule(out)
    assert result.signer_id == "alice"
    assert result.algorithm == "Ed25519"


def test_seal_and_verify_exec_receipt(tmp_path: Path) -> None:
    out = tmp_path / "infer.qcap"
    _, subject = seal_capsule(
        payload_paths=[RUN_RECORD],
        out_path=out,
        signer="support-router",
        algorithm=resolve_algorithm("ed25519"),
    )
    assert subject == "inference"
    result = verify_capsule(out)
    assert result.signer_id == "support-router"


def test_tamper_payload_fails_verify(tmp_path: Path) -> None:
    out = tmp_path / "test.qcap"
    seal_capsule(
        payload_paths=[MODELCARD],
        out_path=out,
        signer="alice",
        algorithm=resolve_algorithm("ed25519"),
    )

    tampered = tmp_path / "tampered-payload.qcap"
    with zipfile.ZipFile(out, "r") as archive:
        names = archive.namelist()
        files = {name: archive.read(name) for name in names}
    files["payload/modelcard.json"] = files["payload/modelcard.json"] + b"tamper"
    with zipfile.ZipFile(tampered, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in files.items():
            archive.writestr(name, data)

    with pytest.raises(VerificationError, match="payload hash mismatch"):
        verify_capsule(tampered)


def test_tamper_record_fails_verify(tmp_path: Path) -> None:
    out = tmp_path / "test.qcap"
    seal_capsule(
        payload_paths=[MODELCARD],
        out_path=out,
        signer="alice",
        algorithm=resolve_algorithm("ed25519"),
    )

    with zipfile.ZipFile(out, "r") as archive:
        names = archive.namelist()
        record = json.loads(archive.read("record.json"))
        manifest = json.loads(archive.read("manifest.json"))
        signature = json.loads(archive.read("signature.json"))
        payloads = {name: archive.read(name) for name in names if name.startswith("payload/")}

    record["signer"]["id"] = "mallory"
    rebuilt = tmp_path / "tampered.qcap"
    with zipfile.ZipFile(rebuilt, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("manifest.json", json.dumps(manifest, indent=2) + "\n")
        archive.writestr("record.json", json.dumps(record, indent=2) + "\n")
        archive.writestr("signature.json", json.dumps(signature, indent=2) + "\n")
        for name, data in payloads.items():
            archive.writestr(name, data)

    with pytest.raises(VerificationError, match="signed_over mismatch|signature invalid"):
        verify_capsule(rebuilt)


def test_append_byte_to_capsule_fails_verify(tmp_path: Path) -> None:
    out = tmp_path / "test.qcap"
    seal_capsule(
        payload_paths=[MODELCARD],
        out_path=out,
        signer="alice",
        algorithm=resolve_algorithm("ed25519"),
    )
    out.write_bytes(out.read_bytes() + b"x")

    with pytest.raises(VerificationError, match="payload hash mismatch"):
        verify_capsule(out)


def test_seal_with_referenced_payload(tmp_path: Path) -> None:
    weights = ROOT / "examples" / "model_custody" / "weights.stub"
    out = tmp_path / "referenced.qcap"
    seal_capsule(
        payload_paths=[MODELCARD],
        referenced_paths=[weights],
        out_path=out,
        signer="alice",
        algorithm=resolve_algorithm("ed25519"),
    )
    result = verify_capsule(out, referenced_payloads={weights.name: weights})
    assert result.signer_id == "alice"

    with zipfile.ZipFile(out, "r") as archive:
        names = archive.namelist()
        assert "payload/modelcard.json" in names
        assert "payload/weights.stub" not in names


def test_hf_seal_model_custody(tmp_path: Path) -> None:
    from qcap.hf import seal_model_custody

    weights = ROOT / "examples" / "model_custody" / "weights.stub"
    out = tmp_path / "custody.qcap"
    seal_model_custody(
        modelcard_path=MODELCARD,
        out_path=out,
        signer="alice",
        weights_path=weights,
    )
    result = verify_capsule(out, referenced_payloads={weights.name: weights})
    assert result.subject_type == "model"


def test_ledger_chain(tmp_path: Path) -> None:
    capsule = tmp_path / "test.qcap"
    ledger = tmp_path / "ledger.jsonl"
    seal_capsule(
        payload_paths=[MODELCARD],
        out_path=capsule,
        signer="alice",
        algorithm=resolve_algorithm("ed25519"),
    )

    add_entry(ledger_path=ledger, capsule_path=capsule)
    assert verify_ledger(ledger) == 1

    add_entry(ledger_path=ledger, capsule_path=capsule)
    assert verify_ledger(ledger) == 2


def test_ledger_tamper_detected(tmp_path: Path) -> None:
    capsule = tmp_path / "test.qcap"
    ledger = tmp_path / "ledger.jsonl"
    seal_capsule(
        payload_paths=[MODELCARD],
        out_path=capsule,
        signer="alice",
        algorithm=resolve_algorithm("ed25519"),
    )
    add_entry(ledger_path=ledger, capsule_path=capsule)

    lines = ledger.read_text(encoding="utf-8").splitlines()
    entry = json.loads(lines[0])
    entry["capsule_id"] = hash_bytes(b"tampered")
    lines[0] = json.dumps(entry)
    ledger.write_text("\n".join(lines) + "\n", encoding="utf-8")

    with pytest.raises(LedgerError, match="entry hash mismatch"):
        verify_ledger(ledger)


def test_cli_verify_requires_capsule() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "qcap.cli", "verify", str(MODELCARD)],
        capture_output=True,
        text=True,
        cwd=ROOT,
    )
    assert result.returncode != 0
