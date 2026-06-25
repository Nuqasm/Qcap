#!/usr/bin/env bash
# #06 — Chain of custody for a model.
set -euo pipefail
cd "$(dirname "$0")"

if command -v qcap >/dev/null 2>&1; then
  QCAP=(qcap)
else
  QCAP=(python -m qcap.cli)
fi

echo "== seal =="
"${QCAP[@]}" seal modelcard.json --out llama-ft.qcap --signer alice

echo
echo "== verify (should pass) =="
"${QCAP[@]}" verify llama-ft.qcap

echo
echo "== tamper one byte =="
printf 'x' >> llama-ft.qcap

echo
echo "== verify (should FAIL) =="
if "${QCAP[@]}" verify llama-ft.qcap; then
  echo "ERROR: tampered capsule verified — that must never happen" >&2
  exit 1
else
  echo "OK: tampered capsule correctly rejected"
fi
