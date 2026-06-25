#!/usr/bin/env bash
# One-command demo: seal → verify → tamper → verify fails → ledger.
set -euo pipefail
cd "$(dirname "$0")/.."

if command -v qcap >/dev/null 2>&1; then
  QCAP=(qcap)
else
  QCAP=(python -m qcap.cli)
fi

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
LEDGER="$TMP/demo.ledger.jsonl"
CAP="$TMP/llama-ft.qcap"

echo "$ qcap seal examples/model_custody/modelcard.json --out llama-ft.qcap --signer alice"
"${QCAP[@]}" seal examples/model_custody/modelcard.json --out "$CAP" --signer alice

echo
echo "$ qcap verify llama-ft.qcap"
"${QCAP[@]}" verify "$CAP"

echo
echo "$ printf 'x' >> llama-ft.qcap"
printf 'x' >> "$CAP"

echo
echo "$ qcap verify llama-ft.qcap"
if "${QCAP[@]}" verify "$CAP"; then
  echo "ERROR: tampered capsule verified" >&2
  exit 1
fi

# Re-seal for ledger step (tampered capsule is unusable)
"${QCAP[@]}" seal examples/model_custody/modelcard.json --out "$CAP" --signer alice >/dev/null

echo
echo "$ qcap ledger add llama-ft.qcap && qcap ledger verify"
"${QCAP[@]}" ledger add "$CAP" --ledger-file "$LEDGER"
"${QCAP[@]}" ledger verify --ledger-file "$LEDGER"
