#!/usr/bin/env python3
"""Example: seal a model-custody .qcap after a Hugging Face hub upload."""

from __future__ import annotations

from pathlib import Path

from qcap.hf import push_to_hub_with_qcap, seal_model_custody

ROOT = Path(__file__).resolve().parent
MODELCARD = ROOT / "modelcard.json"
WEIGHTS = ROOT / "weights.stub"
QCAP_OUT = ROOT / "llama-ft.qcap"


def seal_only() -> None:
    seal_model_custody(
        modelcard_path=MODELCARD,
        out_path=QCAP_OUT,
        signer="alice",
        weights_path=WEIGHTS,
    )
    print(f"sealed {QCAP_OUT} (modelcard embedded, weights referenced by hash)")


def seal_and_upload(repo_id: str, token: str | None = None) -> None:
    push_to_hub_with_qcap(
        modelcard_path=MODELCARD,
        qcap_path=QCAP_OUT,
        signer="alice",
        weights_path=WEIGHTS,
        repo_id=repo_id,
        token=token,
    )
    print(f"uploaded {QCAP_OUT.name} to {repo_id}")


if __name__ == "__main__":
    seal_only()
