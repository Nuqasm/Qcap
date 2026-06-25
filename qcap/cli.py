"""qcap CLI — seal, verify, and ledger commands."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from qcap.capsule import CapsuleError, VerificationError, seal_capsule, verify_capsule
from qcap.ledger import DEFAULT_LEDGER, LedgerError, add_entry, verify_ledger
from qcap.sign import resolve_algorithm


def _out(text: str) -> None:
    try:
        print(text)
    except UnicodeEncodeError:
        print(text.encode("ascii", "replace").decode("ascii"))


def _parse_reference(spec: str) -> tuple[str, Path]:
    if "=" in spec:
        name, path_text = spec.split("=", 1)
        name = name.strip()
        if not name:
            raise ValueError(f"invalid reference spec: {spec!r}")
        return name, Path(path_text)
    path = Path(spec)
    return path.name, path


def _reference_map(specs: list[str]) -> dict[str, Path]:
    mapping: dict[str, Path] = {}
    for spec in specs:
        name, path = _parse_reference(spec)
        mapping[name] = path
    return mapping


def _cmd_seal(args: argparse.Namespace) -> int:
    payload_paths = [Path(path) for path in args.payloads]
    referenced_paths = [Path(spec) for spec in args.reference]
    algorithm = resolve_algorithm(args.algorithm) if args.algorithm else None
    try:
        algo_name, subject = seal_capsule(
            payload_paths=payload_paths,
            referenced_paths=referenced_paths or None,
            out_path=Path(args.out),
            signer=args.signer,
            subject_type=args.subject_type,
            algorithm=algorithm,
        )
    except (CapsuleError, ValueError, RuntimeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    print(f"sealed {args.out}   algorithm={algo_name}  signer={args.signer}  subject={subject}")
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    try:
        result = verify_capsule(
            Path(args.capsule),
            referenced_payloads=_reference_map(args.reference),
        )
    except VerificationError as exc:
        _out(f"✗ VERIFICATION FAILED — {exc.reason}")
        return 1
    except CapsuleError as exc:
        _out(f"✗ VERIFICATION FAILED — {exc}")
        return 1

    _out(f"✓ signature valid ({result.algorithm})")
    _out("✓ payload hashes match manifest")
    _out(f"✓ signer: {result.signer_id}")
    if result.unverified_references:
        refs = ", ".join(result.unverified_references)
        _out(f"⚠ unverified-reference: {refs} (commitment stands; bytes not presented)")
    _out("✓ no network used")
    return 0


def _cmd_ledger_add(args: argparse.Namespace) -> int:
    ledger_path = Path(args.ledger_file)
    try:
        entry = add_entry(ledger_path=ledger_path, capsule_path=Path(args.capsule))
    except (LedgerError, CapsuleError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    _out(f"✓ appended entry seq={entry['seq']} capsule_id={entry['capsule_id']}")
    return 0


def _cmd_ledger_verify(args: argparse.Namespace) -> int:
    ledger_path = Path(args.ledger_file)
    try:
        count = verify_ledger(ledger_path)
    except LedgerError as exc:
        _out(f"✗ LEDGER VERIFICATION FAILED — {exc}")
        return 1
    _out(f"✓ ledger chain intact ({count} {'entry' if count == 1 else 'entries'})")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="qcap", description="Seal and verify .qcap provenance capsules")
    sub = parser.add_subparsers(dest="command", required=True)

    seal = sub.add_parser("seal", help="Seal payload files into a signed .qcap capsule")
    seal.add_argument("payloads", nargs="+", help="One or more payload files to embed")
    seal.add_argument(
        "--reference",
        action="append",
        default=[],
        metavar="PATH",
        help="Hash-commit a file by reference (bytes live outside the capsule)",
    )
    seal.add_argument("--out", required=True, help="Output .qcap path")
    seal.add_argument("--signer", required=True, help="Signer identifier recorded in the audit record")
    seal.add_argument(
        "--subject-type",
        choices=["model", "inference", "agent_action", "quantum_circuit"],
        help="Subject type (default: infer from payload JSON or 'model')",
    )
    seal.add_argument(
        "--algorithm",
        choices=["ml-dsa-87", "ml-dsa-65", "ed25519"],
        help="Signing algorithm (default: ML-DSA-87 when liboqs is available, else Ed25519)",
    )
    seal.set_defaults(func=_cmd_seal)

    verify = sub.add_parser("verify", help="Verify a .qcap capsule offline")
    verify.add_argument("capsule", help="Path to .qcap file")
    verify.add_argument(
        "--reference",
        action="append",
        default=[],
        metavar="NAME=PATH",
        help="Supply bytes for a referenced payload (default name: basename of PATH)",
    )
    verify.set_defaults(func=_cmd_verify)

    ledger = sub.add_parser("ledger", help="Append-only hash-chained ledger")
    ledger_sub = ledger.add_subparsers(dest="ledger_command", required=True)

    ledger_add = ledger_sub.add_parser("add", help="Append a capsule to the ledger")
    ledger_add.add_argument("capsule", help="Path to .qcap file")
    ledger_add.add_argument(
        "--ledger-file",
        default=str(DEFAULT_LEDGER),
        help=f"Ledger JSONL path (default: {DEFAULT_LEDGER})",
    )
    ledger_add.set_defaults(func=_cmd_ledger_add)

    ledger_verify = ledger_sub.add_parser("verify", help="Verify ledger chain integrity")
    ledger_verify.add_argument(
        "--ledger-file",
        default=str(DEFAULT_LEDGER),
        help=f"Ledger JSONL path (default: {DEFAULT_LEDGER})",
    )
    ledger_verify.set_defaults(func=_cmd_ledger_verify)

    return parser


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    raise SystemExit(args.func(args))


if __name__ == "__main__":
    main()
