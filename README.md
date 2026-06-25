# qcap

**Verifiable execution provenance and chain of custody for AI — open, offline, tamper-evident.**

[![CI](https://github.com/Nuqasm/Qcap/actions/workflows/ci.yml/badge.svg)](https://github.com/Nuqasm/Qcap/actions/workflows/ci.yml) [![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE) [![PQC](https://img.shields.io/badge/signatures-ML--DSA--87-7b3fe4)](#cryptography)

A `.qcap` is a signed, tamper-evident receipt that proves *which model and code ran, on what hardware, under whose authorization, and what it produced.* Anyone can produce one and verify it **offline, with no account and no service in the loop.** This repository is the open trust-bearing core: the capsule format, the verifier, and the audit-record schema.

It started life proving what regulated **quantum** workloads actually ran. The same receipt is substrate-agnostic — it doesn't care whether the thing inside is a quantum circuit, a model checkpoint, an inference run, or an agent's tool call.

---

## Claim → artifact map

Every open capability named in the product application points to a concrete file in this repository:

| Open claim | Artifact |
|---|---|
| `.qcap` format specification | [`SPEC.md`](SPEC.md) |
| Offline tamper-evident verification | [`qcap/capsule.py`](qcap/capsule.py), [`qcap/cli.py`](qcap/cli.py) |
| `seal` / `verify` CLI | [`qcap/cli.py`](qcap/cli.py) |
| ML-DSA-87 + Ed25519 signing | [`qcap/sign.py`](qcap/sign.py) |
| Audit record JSON Schema | [`schema/audit-record.schema.json`](schema/audit-record.schema.json) |
| Append-only hash-chained ledger | [`qcap/ledger.py`](qcap/ledger.py) |
| Referenced large-artifact commitments | [`qcap/capsule.py`](qcap/capsule.py) (`--reference`) |
| Model chain of custody (#06) | [`examples/model_custody/`](examples/model_custody/) |
| Execution receipt (#07) | [`examples/exec_receipt/`](examples/exec_receipt/) |
| Hugging Face `push_to_hub` hook | [`qcap/hf.py`](qcap/hf.py), [`examples/model_custody/push_to_hub_example.py`](examples/model_custody/push_to_hub_example.py) |
| Runnable demo (<2 min) | [`demo/demo.sh`](demo/demo.sh), [`demo/colab.ipynb`](demo/colab.ipynb) |
| Tamper-evidence conformance tests | [`tests/test_roundtrip.py`](tests/test_roundtrip.py), [`tests/tamper/`](tests/tamper/) |
| CI (green = runnable) | [`.github/workflows/ci.yml`](.github/workflows/ci.yml) |
| Apache-2.0 open core | [`LICENSE`](LICENSE) |

---

## Why this exists

Models and agents now make consequential decisions as opaque services that leave almost no verifiable trace. Weights, prompts, tools, or hardware can be swapped and no one downstream can tell. `qcap` closes two specific gaps:

| Gap | What `qcap` gives you | Example |
|---|---|---|
| **Chain of custody for models** | Sign a model's identity and lineage — base model, training-data manifest, fine-tunes, safety filters — into a tamper-evident receipt. | [`examples/model_custody/`](examples/model_custody/) |
| **Proof an AI did what it claims** | Bind an output to a specific model, code path, and authorization scope, verifiable before anyone trusts the decision. | [`examples/exec_receipt/`](examples/exec_receipt/) |

---

## Quickstart (under 2 minutes)

```bash
pip install -e .
bash demo/demo.sh
```

Or run it in your browser with zero install: **[Open in Colab](https://colab.research.google.com/github/Nuqasm/Qcap/blob/main/demo/colab.ipynb)**.

You should see this:

```
$ qcap seal examples/model_custody/modelcard.json --out llama-ft.qcap --signer alice
sealed llama-ft.qcap   algorithm=ML-DSA-87  signer=alice  subject=model

$ qcap verify llama-ft.qcap
✓ signature valid (ML-DSA-87)
✓ payload hashes match manifest
✓ signer: alice
✓ no network used

$ printf 'x' >> llama-ft.qcap          # tamper with a single byte

$ qcap verify llama-ft.qcap
✗ VERIFICATION FAILED — payload hash mismatch (capsule has been modified)

$ qcap ledger add llama-ft.qcap && qcap ledger verify
✓ ledger chain intact (1 entry)
```

The last two commands are the point: change one byte and verification fails. That is the whole tamper-evidence guarantee, and you just ran it yourself.

> **Signer in the demo:** by default the demo uses **ML-DSA-87** (FIPS 204, CNSA 2.0)
> when `liboqs` is present (`pip install -e ".[pqc]"`). On environments without it —
> including a bare Colab runtime — it falls back to **Ed25519** and prints which
> algorithm ran. The format, verification, and tamper-evidence are identical either way;
> only the signature primitive changes.

---

## What's in a `.qcap`

A `.qcap` is a ZIP containing three files:

- **`manifest.json`** — every payload entry with its SHA-256 content hash and a `subject_type` (`model` · `inference` · `agent_action` · `quantum_circuit`).
- **`record.json`** — the audit record (conforms to [`schema/audit-record.schema.json`](schema/audit-record.schema.json)): signer identity, timestamp, environment, payload hashes, and an optional `hardware_attestation` field.
- **`signature.json`** — `{ algorithm, public_key, signature }` over the canonical bytes of `manifest.json` + `record.json`.

**Verification is offline:** recompute the payload hashes, recompute the canonical bytes, check the signature against the embedded public key. Any change to any byte breaks a hash, which breaks the signature. No network, no callback, no trust in us required. Full format in [`SPEC.md`](SPEC.md).

---

## Cryptography

Signing is pluggable, and the CLI always prints which algorithm ran so nothing is ambiguous:

- **ML-DSA-87** (FIPS 204, CNSA 2.0) via `liboqs` / `oqs-python` — the default when available (`pip install -e ".[pqc]"`).
- **Ed25519** (stdlib) — a zero-dependency fallback so the demo runs green on any machine, including ones where `liboqs` won't build.

```bash
qcap seal model.json --out m.qcap --signer alice --algorithm ml-dsa-87   # explicit
qcap verify m.qcap                                                       # algorithm read from the capsule
```

---

## CLI

```
qcap seal <payload...> --out <file.qcap> --signer <id> [--reference PATH...] [--algorithm ml-dsa-87|ed25519]
qcap verify <file.qcap> [--reference NAME=PATH...]   # offline; exits non-zero on any tamper
qcap ledger add <file.qcap>             # append to a hash-chained, append-only log
qcap ledger verify                      # confirm the chain has not been edited or reordered
```

Reference large artifacts (e.g. model weights) by hash without embedding them:

```bash
qcap seal modelcard.json --reference weights.safetensors --out custody.qcap --signer alice
qcap verify custody.qcap --reference weights.safetensors=./weights.safetensors
```

The append-only ledger is hash-chained JSONL — each entry carries the previous entry's hash, so editing or reordering history fails `ledger verify`.

---

## What is and isn't here

**Open (this repo, Apache-2.0):** the `.qcap` format, the `seal`/`verify` CLI, the audit-record schema, and the append-only ledger. This is the trust-bearing core — the part that has to be open for a receipt to mean anything. Use it as the provenance backbone for your own models and agents, no strings.

**Not here (commercial):** the managed ledger service, compliance dashboards, policy routing, the air-gapped appliance, and regulatory control-mappings (NIST SP 800-53, 21 CFR Part 11). These reuse the exact same open receipts; they don't replace them.

---

## Roadmap

- An agent-framework wrapper (LangGraph / LangChain) that signs each tool call with the active model, code path, and authorization scope.

---

## Background

The provenance and auditability model here builds on *From Trustworthy AI to Trustworthy Quantum: a governance framework for auditable quantum computation in regulated decisions* (S. Vemula, IEEE Quantum Week, QCE26). See [`SPEC.md`](SPEC.md) for how the framework maps to the on-disk format.

## License

Apache-2.0. See [`LICENSE`](LICENSE).
