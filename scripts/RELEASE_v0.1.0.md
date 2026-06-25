# qcap v0.1.0 — first public release

The open, trust-bearing core of execution provenance for AI: produce a signed,
tamper-evident `.qcap` receipt and verify it **offline, with no account and no
service in the loop.**

## What's included
- **`.qcap` format** — a ZIP of `manifest.json` + `record.json` + `signature.json`,
  fully specified in [`SPEC.md`](SPEC.md) (implementable from the spec alone).
- **`seal` / `verify` / `ledger` CLI** — offline verification that exits non-zero on
  any tamper; a hash-chained append-only ledger.
- **Signing** — ML-DSA-87 (FIPS 204 / CNSA 2.0) via liboqs, with an Ed25519
  zero-dependency fallback.
- **Audit-record JSON Schema**, and two runnable examples:
  model chain of custody (#06) and execution receipt (#07).
- **Referenced large artifacts** — commit model weights by hash without embedding them.

## Try it (under 2 minutes)
```bash
pip install -e .
bash demo/demo.sh
```
Seal a model card, verify it, change one byte, watch verification fail.
Browser, zero install: see the Colab link in the README.

## Scope and known limits (v0.1)
- Verification proves **integrity and authenticity** — that nothing changed and the
  named key signed it. It does **not** prove the signer's real-world identity
  (key distribution is out of scope) or that the asserted timestamp is true.
- `hardware_attestation` is present in the schema but **null** in the open core;
  it's populated by the commercial runtime.
- Trusted timestamping, hardware-attestation schemas, and countersignatures are
  reserved for later versions (see SPEC §10). 0.1 verifiers ignore unknown fields.

## License
Apache-2.0.
