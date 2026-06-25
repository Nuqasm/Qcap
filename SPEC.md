# `.qcap` Format Specification

**Version:** 0.1 (draft)
**Status:** reference implementation in this repository
**License:** Apache-2.0

This document defines the `.qcap` capsule: a portable, signed, tamper-evident record of an execution or artifact, verifiable offline with no network access and no trust in the issuer. It is deliberately small. A capsule is a ZIP archive of three JSON files plus an optional payload directory; verification is recompute-and-check, nothing more.

A reader who follows this document can implement an independent verifier from scratch. That is the test the format is designed to pass.

---

## 1. Design goals

1. **Offline-verifiable.** Verification requires only the capsule and a public key embedded in it. No service, no registry, no clock authority.
2. **Tamper-evident.** Any change to any payload byte or any record field invalidates the signature. There is no "partial trust."
3. **Substrate-agnostic.** The same format covers a model checkpoint, an inference run, an agent action, or a quantum circuit. The `subject_type` field distinguishes them; the verification logic does not change.
4. **Boringly auditable.** Canonicalization, hashing, and signing are standard primitives with no custom cryptography.

Non-goals: confidentiality (a capsule is integrity-and-authenticity, not encryption), access control, and long-term key management. Those belong to layers above this format.

---

## 2. Container

A `.qcap` is a ZIP archive (PKZIP, store or deflate) with this layout:

```
capsule.qcap
├── manifest.json        # required
├── record.json          # required
├── signature.json       # required
└── payload/             # optional; present when payloads are embedded rather than referenced
    └── <files…>
```

The three top-level JSON files MUST be present. The `payload/` directory is OPTIONAL: payloads may be embedded (stored under `payload/`) or referenced by hash only (for large artifacts such as model weights that live elsewhere). Either way, the hash in `manifest.json` is authoritative.

---

## 3. Canonicalization

All hashing and signing operate on **canonical JSON bytes**, defined as:

- UTF-8 encoding, no BOM.
- Object keys sorted lexicographically by Unicode code point.
- No insignificant whitespace (no spaces or newlines between tokens).
- Numbers serialized without leading zeros, without a trailing decimal point, and without exponent notation where an integer suffices.

This is the JSON Canonicalization Scheme (RFC 8785) profile. Two implementations that follow it MUST produce byte-identical output for the same logical document. Canonical bytes are written `canon(x)` below.

---

## 4. Hashing

The content hash function is **SHA-256**, lowercase hex, prefixed with the algorithm label:

```
hash(bytes) = "sha256:" + hex(SHA-256(bytes))
```

Payload hashes are computed over the raw payload bytes (not canonicalized — payloads are arbitrary files). Record and manifest hashes are computed over their canonical bytes.

---

## 5. `manifest.json`

Inventory of everything the capsule vouches for.

```json
{
  "qcap_version": "0.1",
  "subject_type": "model",
  "payloads": [
    {
      "name": "modelcard.json",
      "location": "embedded",
      "hash": "sha256:9f2c…",
      "media_type": "application/json"
    },
    {
      "name": "model.safetensors",
      "location": "referenced",
      "hash": "sha256:4ab1…",
      "media_type": "application/octet-stream"
    }
  ]
}
```

Fields:

| Field | Type | Notes |
|---|---|---|
| `qcap_version` | string | MUST match a version this spec defines (`"0.1"`). |
| `subject_type` | enum | `model` · `inference` · `agent_action` · `quantum_circuit`. |
| `payloads[]` | array | One entry per payload. MUST be non-empty. |
| `payloads[].name` | string | Filename; if `location` is `embedded`, this is the path under `payload/`. |
| `payloads[].location` | enum | `embedded` (bytes are in the capsule) or `referenced` (bytes live elsewhere; only the hash is committed). |
| `payloads[].hash` | string | `sha256:…` over the payload bytes. |
| `payloads[].media_type` | string | Advisory. |

---

## 6. `record.json` (the audit record)

The claim being signed. Conforms to `schema/audit-record.schema.json`.

```json
{
  "qcap_version": "0.1",
  "subject_type": "model",
  "signer": { "id": "alice", "display": "Alice Researcher" },
  "timestamp": "2026-06-25T14:02:11Z",
  "environment": {
    "runtime": "qcap-ref/0.1",
    "host": "build-node-3",
    "backend": null
  },
  "subject": {
    "manifest_hash": "sha256:1c0d…",
    "lineage": {
      "base_model": "meta-llama/Llama-3-8B",
      "training_data_manifest": "sha256:77af…",
      "fine_tunes": ["sha256:90b2…"],
      "safety_filters": ["nsfw-classifier@1.4"]
    }
  },
  "authorization": { "scope": "fine-tune", "granted_by": "alice" },
  "hardware_attestation": null
}
```

Fields:

| Field | Type | Notes |
|---|---|---|
| `qcap_version` | string | MUST equal the manifest's. |
| `subject_type` | enum | MUST equal the manifest's. |
| `signer` | object | `id` is required and is what `verify` reports. |
| `timestamp` | string | RFC 3339, UTC (`Z`). Self-asserted; trusted timestamping is a future extension (§10). |
| `environment` | object | Free-form but schema-constrained; `backend` names hardware/cloud when relevant (e.g. `ibm_kyoto`), else `null`. |
| `subject.manifest_hash` | string | `sha256:` over `canon(manifest.json)`. **This binds the record to the manifest.** |
| `subject.lineage` | object | OPTIONAL; populated for `subject_type: model` (#06). Shape shown above. |
| `authorization` | object | OPTIONAL; populated for `inference` / `agent_action` (#07): what scope the run was permitted. |
| `hardware_attestation` | object \| null | OPTIONAL; `null` in the open core. The commercial runtime populates a TEE/quote object here. Its presence or absence does not change verification of the rest. |

The record binds to the manifest via `subject.manifest_hash`. The signature (next) binds to both.

---

## 7. `signature.json`

```json
{
  "algorithm": "ML-DSA-87",
  "public_key": "base64…",
  "signed_over": "sha256:e4d0…",
  "signature": "base64…"
}
```

`signed_over` is `hash(canon(manifest.json) || canon(record.json))`, where `||` is byte concatenation. `signature` is the signature over those same concatenated canonical bytes (not over the hash) using the named algorithm.

Supported algorithms:

| `algorithm` | Standard | Use |
|---|---|---|
| `ML-DSA-87` | FIPS 204 / CNSA 2.0 | Default when `liboqs` is available. |
| `ML-DSA-65` | FIPS 204 | Lower-parameter PQC option. |
| `Ed25519` | RFC 8032 | Zero-dependency fallback for frictionless demos. |

The verifier reads `algorithm` from the capsule; the producer's choice is recorded honestly and is not negotiable at verify time.

---

## 8. Verification procedure

Given a capsule, a conforming verifier MUST:

1. Open the ZIP; load `manifest.json`, `record.json`, `signature.json`.
2. Check `qcap_version` is supported and that `subject_type` matches across manifest and record.
3. For each `embedded` payload: recompute `hash(bytes)` and compare to the manifest entry. For each `referenced` payload: if the bytes are supplied out-of-band, hash and compare; otherwise mark **unverified-reference** (the commitment stands, the bytes were not presented).
4. Recompute `hash(canon(manifest.json))` and compare to `record.subject.manifest_hash`.
5. Recompute `canon(manifest.json) || canon(record.json)`; verify `signature` against `public_key` using `algorithm`.
6. Recompute `signed_over` and confirm it equals the recomputed hash of those bytes.

If steps 2–6 all pass, the capsule is **valid**: its payloads are unmodified and the record was signed by the holder of `public_key`. Any failure MUST cause a non-zero exit and a specific reason. **No network access is permitted at any step.**

What validity does and does not mean: it proves integrity (nothing changed since signing) and authenticity (the named key signed it). It does **not** prove the signer's real-world identity — that is a key-distribution problem outside this format — nor that the asserted timestamp is true absent a timestamp extension (§10).

---

## 9. Append-only ledger (companion, not part of the capsule)

A ledger is hash-chained JSONL. Each line:

```json
{ "seq": 7, "ts": "2026-06-25T14:02:12Z", "capsule_id": "sha256:e4d0…",
  "prev_hash": "sha256:aa19…", "entry_hash": "sha256:bb73…" }
```

`capsule_id` is `signed_over` from the capsule. `prev_hash` is the previous line's `entry_hash` (genesis uses all-zero). `entry_hash` is `hash(canon(line-without-entry_hash))`. Editing or reordering any line breaks the chain and fails `ledger verify`. The ledger records *that* a capsule existed and *when it was seen*; it does not alter capsule verification.

---

## 10. Reserved extensions (not in 0.1)

- **Trusted timestamping** — an RFC 3161 token or transparency-log inclusion proof bound into `record.json`, to make `timestamp` independently checkable.
- **Hardware attestation** — a concrete schema for `hardware_attestation` (TEE quotes, device certificates).
- **Countersignatures** — multiple `signature.json` entries for multi-party custody.

These are named so implementers leave room; 0.1 verifiers MUST ignore unknown top-level fields rather than fail on them.

---

## 11. Conformance

An implementation conforms to `.qcap` 0.1 if it (a) produces capsules that the reference verifier in this repository accepts, and (b) accepts every capsule the reference implementation produces, and (c) rejects every capsule in `tests/` marked `tamper`. Interop is defined by behavior against the reference, not by shared code.
