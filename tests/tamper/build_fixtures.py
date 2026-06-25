"""Build tamper-marked .qcap fixtures for conformance tests (SPEC §11)."""

from __future__ import annotations

import json
import zipfile
from pathlib import Path

from qcap.capsule import TAMPER_FAILURE, seal_capsule, verify_capsule
from qcap.sign import resolve_algorithm

ROOT = Path(__file__).resolve().parents[2]
TAMPER_DIR = Path(__file__).resolve().parent
MODELCARD = ROOT / "examples" / "model_custody" / "modelcard.json"
WEIGHTS = ROOT / "examples" / "model_custody" / "weights.stub"
INDEX_PATH = TAMPER_DIR / "index.json"


def _write_index(entries: list[dict]) -> None:
    INDEX_PATH.write_text(json.dumps({"fixtures": entries}, indent=2) + "\n", encoding="utf-8")


def build_fixtures() -> None:
    TAMPER_DIR.mkdir(parents=True, exist_ok=True)
    algo = resolve_algorithm("ed25519")
    entries: list[dict] = []

    valid_path = TAMPER_DIR / "valid.qcap"
    seal_capsule(
        payload_paths=[MODELCARD],
        referenced_paths=[WEIGHTS],
        out_path=valid_path,
        signer="alice",
        algorithm=algo,
    )
    verify_capsule(valid_path, referenced_payloads={WEIGHTS.name: WEIGHTS})
    entries.append({"file": valid_path.name, "tamper": False, "note": "valid capsule with referenced weights"})

    append_path = TAMPER_DIR / "tamper-append-byte.qcap"
    seal_capsule(
        payload_paths=[MODELCARD],
        out_path=append_path,
        signer="alice",
        algorithm=algo,
    )
    append_path.write_bytes(append_path.read_bytes() + b"x")
    entries.append({"file": append_path.name, "tamper": True, "note": "single trailing byte appended"})

    payload_path = TAMPER_DIR / "tamper-payload.qcap"
    seal_capsule(
        payload_paths=[MODELCARD],
        out_path=payload_path,
        signer="alice",
        algorithm=algo,
    )
    with zipfile.ZipFile(payload_path, "r") as archive:
        files = {name: archive.read(name) for name in archive.namelist()}
    files["payload/modelcard.json"] = files["payload/modelcard.json"] + b"tamper"
    with zipfile.ZipFile(payload_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in files.items():
            archive.writestr(name, data)
    entries.append({"file": payload_path.name, "tamper": True, "note": "embedded payload bytes modified"})

    record_path = TAMPER_DIR / "tamper-record.qcap"
    seal_capsule(
        payload_paths=[MODELCARD],
        out_path=record_path,
        signer="alice",
        algorithm=algo,
    )
    with zipfile.ZipFile(record_path, "r") as archive:
        names = archive.namelist()
        record = json.loads(archive.read("record.json"))
        manifest = json.loads(archive.read("manifest.json"))
        signature = json.loads(archive.read("signature.json"))
        payloads = {name: archive.read(name) for name in names if name.startswith("payload/")}
    record["signer"]["id"] = "mallory"
    with zipfile.ZipFile(record_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("manifest.json", json.dumps(manifest, indent=2) + "\n")
        archive.writestr("record.json", json.dumps(record, indent=2) + "\n")
        archive.writestr("signature.json", json.dumps(signature, indent=2) + "\n")
        for name, data in payloads.items():
            archive.writestr(name, data)
    entries.append({"file": record_path.name, "tamper": True, "note": "audit record modified after signing"})

    _write_index(entries)
    print(f"built {len(entries)} fixtures in {TAMPER_DIR}")
    print(f"expected tamper failure message: {TAMPER_FAILURE!r}")


if __name__ == "__main__":
    build_fixtures()
