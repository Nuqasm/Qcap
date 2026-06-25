#!/usr/bin/env bash
# #07 — Proof an AI did what it claims.
set -euo pipefail
cd "$(dirname "$0")"

if command -v qcap >/dev/null 2>&1; then
  QCAP=(qcap)
else
  QCAP=(python -m qcap.cli)
fi

echo "== seal =="
"${QCAP[@]}" seal run_record.json --out infer.qcap --signer support-router

echo
echo "== verify (offline) =="
"${QCAP[@]}" verify infer.qcap

echo
echo "Receipt proves: this output came from model 'acme/llama-3-8b-support-ft'"
echo "and code 'serve.py:classify', under scope 'classify-only' — nothing else."
