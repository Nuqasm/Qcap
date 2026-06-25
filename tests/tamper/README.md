# Tamper fixtures (SPEC §11)

Pre-built `.qcap` files used by `tests/test_tamper_fixtures.py`. Regenerate with:

```bash
python tests/tamper/build_fixtures.py
```

| File | `tamper` | Expected result |
|---|---|---|
| `valid.qcap` | false | verify passes (with referenced `weights.stub`) |
| `tamper-append-byte.qcap` | true | verify fails — `payload hash mismatch (capsule has been modified)` |
| `tamper-payload.qcap` | true | verify fails — payload hash mismatch |
| `tamper-record.qcap` | true | verify fails — signature / signed_over mismatch |

The index of record is in [`index.json`](index.json).
