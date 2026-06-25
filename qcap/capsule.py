"""Build, open, and verify .qcap ZIP capsules."""

from __future__ import annotations

import io
import json
import mimetypes
import socket
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from qcap import __version__
from qcap.canon import canon
from qcap.hashing import hash_bytes, hash_canonical, hash_file
from qcap.sign import Algorithm, KeyPair, resolve_algorithm, sign_bytes, verify_bytes

QCAP_VERSION = "0.1"
SUPPORTED_VERSIONS = {QCAP_VERSION}
SUBJECT_TYPES = {"model", "inference", "agent_action", "quantum_circuit"}

MANIFEST_NAME = "manifest.json"
RECORD_NAME = "record.json"
SIGNATURE_NAME = "signature.json"
PAYLOAD_PREFIX = "payload/"
ZIP_EOCD_SIGNATURE = b"PK\x05\x06"
TAMPER_FAILURE = "payload hash mismatch (capsule has been modified)"


def _zip_archive_length(data: bytes) -> int:
    eocd_offset = data.rfind(ZIP_EOCD_SIGNATURE)
    if eocd_offset < 0:
        raise VerificationError("capsule is not a valid ZIP archive (capsule has been modified)")
    comment_length = int.from_bytes(data[eocd_offset + 20 : eocd_offset + 22], "little")
    return eocd_offset + 22 + comment_length


class CapsuleError(Exception):
    """Base error for capsule operations."""


class VerificationError(CapsuleError):
    """Verification failed with a human-readable reason."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


@dataclass
class VerifyResult:
    algorithm: str
    signer_id: str
    subject_type: str
    signed_over: str
    unverified_references: list[str]


def _guess_media_type(path: Path) -> str:
    media_type, _ = mimetypes.guess_type(path.name)
    return media_type or "application/octet-stream"


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _hostname() -> str:
    try:
        return socket.gethostname()
    except OSError:
        return "unknown"


def _load_json_from_zip(archive: zipfile.ZipFile, name: str) -> dict[str, Any]:
    try:
        raw = archive.read(name)
    except KeyError as exc:
        raise VerificationError(f"missing required file: {name}") from exc
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise VerificationError(f"invalid JSON in {name}") from exc


def _read_payload_metadata(path: Path) -> dict[str, Any] | None:
    if path.suffix.lower() != ".json":
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def infer_subject_type(payload_paths: list[Path]) -> str:
    for path in payload_paths:
        meta = _read_payload_metadata(path)
        if meta and meta.get("subject_type") in SUBJECT_TYPES:
            return str(meta["subject_type"])
    return "model"


def build_record(
    *,
    subject_type: str,
    signer: str,
    manifest: dict[str, Any],
    payload_paths: list[Path],
) -> dict[str, Any]:
    manifest_hash = hash_canonical(manifest)
    record: dict[str, Any] = {
        "qcap_version": QCAP_VERSION,
        "subject_type": subject_type,
        "signer": {"id": signer, "display": signer},
        "timestamp": _utc_now(),
        "environment": {
            "runtime": f"qcap-ref/{__version__}",
            "host": _hostname(),
            "backend": None,
        },
        "subject": {"manifest_hash": manifest_hash},
        "hardware_attestation": None,
    }

    if subject_type == "model":
        record["subject"]["lineage"] = _model_lineage(payload_paths)
    elif subject_type in {"inference", "agent_action"}:
        auth = _authorization_from_payload(payload_paths)
        if auth is not None:
            record["authorization"] = auth

    return record


def _model_lineage(payload_paths: list[Path]) -> dict[str, Any]:
    lineage: dict[str, Any] = {}
    for path in payload_paths:
        meta = _read_payload_metadata(path)
        if not meta:
            continue
        if "base_model" in meta:
            lineage["base_model"] = meta["base_model"]
        training = meta.get("training_data_manifest")
        if isinstance(training, dict) and "hash" in training:
            lineage["training_data_manifest"] = training["hash"]
        elif isinstance(training, str):
            lineage["training_data_manifest"] = training
        fine_tunes = meta.get("fine_tunes")
        if isinstance(fine_tunes, list):
            lineage["fine_tunes"] = [
                item["hash"] if isinstance(item, dict) and "hash" in item else item for item in fine_tunes
            ]
        safety = meta.get("safety_filters")
        if isinstance(safety, list):
            lineage["safety_filters"] = safety
        if lineage:
            break
    return lineage


def _authorization_from_payload(payload_paths: list[Path]) -> dict[str, Any] | None:
    for path in payload_paths:
        meta = _read_payload_metadata(path)
        if meta and isinstance(meta.get("authorization"), dict):
            return meta["authorization"]
    return None


def build_manifest(
    *,
    subject_type: str,
    embedded_paths: list[Path],
    referenced_paths: list[Path] | None = None,
) -> dict[str, Any]:
    payloads = []
    for path in embedded_paths:
        payloads.append(
            {
                "name": path.name,
                "location": "embedded",
                "hash": hash_file(path),
                "media_type": _guess_media_type(path),
            }
        )
    for path in referenced_paths or []:
        payloads.append(
            {
                "name": path.name,
                "location": "referenced",
                "hash": hash_file(path),
                "media_type": _guess_media_type(path),
            }
        )
    return {
        "qcap_version": QCAP_VERSION,
        "subject_type": subject_type,
        "payloads": payloads,
    }


def _all_payload_paths(embedded_paths: list[Path], referenced_paths: list[Path] | None) -> list[Path]:
    return embedded_paths + list(referenced_paths or [])


def seal_capsule(
    *,
    payload_paths: list[Path],
    out_path: Path,
    signer: str,
    subject_type: str | None = None,
    algorithm: Algorithm | None = None,
    keypair: KeyPair | None = None,
    referenced_paths: list[Path] | None = None,
) -> tuple[str, str]:
    if not payload_paths:
        raise CapsuleError("at least one embedded payload file is required")

    embedded_paths = [path.resolve() for path in payload_paths]
    resolved_references = [path.resolve() for path in (referenced_paths or [])]
    for path in embedded_paths + resolved_references:
        if not path.is_file():
            raise CapsuleError(f"payload not found: {path}")

    all_paths = _all_payload_paths(embedded_paths, resolved_references)
    resolved_subject = subject_type or infer_subject_type(all_paths)
    if resolved_subject not in SUBJECT_TYPES:
        raise CapsuleError(f"unsupported subject_type: {resolved_subject}")

    manifest = build_manifest(
        subject_type=resolved_subject,
        embedded_paths=embedded_paths,
        referenced_paths=resolved_references,
    )
    record = build_record(
        subject_type=resolved_subject,
        signer=signer,
        manifest=manifest,
        payload_paths=all_paths,
    )

    signed_material = canon(manifest) + canon(record)
    algo = resolve_algorithm(algorithm)
    keys = keypair or algo.generate_keypair()
    signature_value = sign_bytes(algo, keys.private_key, signed_material)

    signature_doc = {
        "algorithm": algo.name,
        "public_key": keys.public_key_b64,
        "signed_over": hash_bytes(signed_material),
        "signature": signature_value,
    }

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(out_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(MANIFEST_NAME, json.dumps(manifest, indent=2) + "\n")
        archive.writestr(RECORD_NAME, json.dumps(record, indent=2) + "\n")
        archive.writestr(SIGNATURE_NAME, json.dumps(signature_doc, indent=2) + "\n")
        for path in embedded_paths:
            archive.write(path, PAYLOAD_PREFIX + path.name)

    return algo.name, resolved_subject


def _verify_open_archive(
    archive: zipfile.ZipFile,
    *,
    referenced_payloads: dict[str, Path],
) -> VerifyResult:
    manifest = _load_json_from_zip(archive, MANIFEST_NAME)
    record = _load_json_from_zip(archive, RECORD_NAME)
    signature_doc = _load_json_from_zip(archive, SIGNATURE_NAME)

    version = manifest.get("qcap_version")
    if version not in SUPPORTED_VERSIONS:
        raise VerificationError(f"unsupported qcap_version: {version!r}")

    manifest_subject = manifest.get("subject_type")
    record_subject = record.get("subject_type")
    if manifest_subject != record_subject:
        raise VerificationError("subject_type mismatch between manifest and record")
    if manifest_subject not in SUBJECT_TYPES:
        raise VerificationError(f"unsupported subject_type: {manifest_subject!r}")

    unverified: list[str] = []
    for entry in manifest.get("payloads", []):
        name = entry.get("name")
        location = entry.get("location")
        expected_hash = entry.get("hash")
        if not name or location not in {"embedded", "referenced"}:
            raise VerificationError("invalid payload entry in manifest")

        if location == "embedded":
            payload_name = PAYLOAD_PREFIX + name
            try:
                payload_bytes = archive.read(payload_name)
            except KeyError as exc:
                raise VerificationError(f"missing embedded payload: {name}") from exc
            actual_hash = hash_bytes(payload_bytes)
        else:
            ref_path = referenced_payloads.get(name)
            if ref_path is None or not ref_path.is_file():
                unverified.append(name)
                continue
            actual_hash = hash_file(ref_path)

        if actual_hash != expected_hash:
            raise VerificationError(TAMPER_FAILURE)

    manifest_hash = hash_canonical(manifest)
    recorded_hash = record.get("subject", {}).get("manifest_hash")
    if manifest_hash != recorded_hash:
        raise VerificationError("manifest hash mismatch (record does not match manifest)")

    signed_material = canon(manifest) + canon(record)
    signed_over = hash_bytes(signed_material)
    if signature_doc.get("signed_over") != signed_over:
        raise VerificationError("signed_over mismatch (signature metadata is inconsistent)")

    algorithm_name = signature_doc.get("algorithm")
    public_key_b64 = signature_doc.get("public_key")
    signature_value = signature_doc.get("signature")
    if not algorithm_name or not public_key_b64 or not signature_value:
        raise VerificationError("signature.json is missing required fields")

    algo = resolve_algorithm(algorithm_name)
    if not verify_bytes(algo, public_key_b64, signed_material, signature_value):
        raise VerificationError("signature invalid (capsule has been modified)")

    signer = record.get("signer", {})
    signer_id = signer.get("id") if isinstance(signer, dict) else None
    if not signer_id:
        raise VerificationError("record is missing signer.id")

    return VerifyResult(
        algorithm=str(algorithm_name),
        signer_id=str(signer_id),
        subject_type=str(manifest_subject),
        signed_over=signed_over,
        unverified_references=unverified,
    )


def verify_capsule(
    capsule_path: Path,
    *,
    referenced_payloads: dict[str, Path] | None = None,
) -> VerifyResult:
    referenced_payloads = referenced_payloads or {}

    if not capsule_path.is_file():
        raise VerificationError(f"capsule not found: {capsule_path}")

    try:
        data = capsule_path.read_bytes()
        archive_length = _zip_archive_length(data)
        if len(data) > archive_length:
            raise VerificationError(TAMPER_FAILURE)
        with zipfile.ZipFile(io.BytesIO(data[:archive_length]), "r") as archive:
            return _verify_open_archive(archive, referenced_payloads=referenced_payloads)
    except OSError as exc:
        raise VerificationError("capsule is not a valid ZIP archive (capsule has been modified)") from exc
    except zipfile.BadZipFile as exc:
        raise VerificationError("capsule is not a valid ZIP archive (capsule has been modified)") from exc


def read_signed_over(capsule_path: Path) -> str:
    with zipfile.ZipFile(capsule_path, "r") as archive:
        signature_doc = _load_json_from_zip(archive, SIGNATURE_NAME)
    signed_over = signature_doc.get("signed_over")
    if not isinstance(signed_over, str):
        raise CapsuleError("capsule is missing signed_over")
    return signed_over
