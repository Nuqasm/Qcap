"""Hugging Face integration — emit .qcap model-custody receipts on hub upload."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from qcap.capsule import seal_capsule
from qcap.sign import resolve_algorithm


def seal_model_custody(
    *,
    modelcard_path: Path | str,
    out_path: Path | str,
    signer: str,
    weights_path: Path | str | None = None,
    reference_weights: bool = True,
    algorithm: str | None = "ed25519",
) -> Path:
    """Seal a model card into a custody .qcap, optionally referencing large weights by hash."""
    modelcard = Path(modelcard_path)
    output = Path(out_path)
    referenced: list[Path] = []
    if weights_path is not None and reference_weights:
        referenced.append(Path(weights_path))

    seal_capsule(
        payload_paths=[modelcard],
        referenced_paths=referenced or None,
        out_path=output,
        signer=signer,
        subject_type="model",
        algorithm=resolve_algorithm(algorithm) if algorithm else None,
    )
    return output


def push_to_hub_with_qcap(
    *,
    modelcard_path: Path | str,
    qcap_path: Path | str,
    signer: str,
    weights_path: Path | str | None = None,
    upload_qcap: bool = True,
    repo_id: str | None = None,
    token: str | None = None,
) -> Path:
    """Seal a custody receipt and optionally upload it alongside a Hub model repo."""
    output = seal_model_custody(
        modelcard_path=modelcard_path,
        out_path=qcap_path,
        signer=signer,
        weights_path=weights_path,
    )
    if not upload_qcap:
        return output

    if repo_id is None:
        raise ValueError("repo_id is required when upload_qcap=True")

    try:
        from huggingface_hub import HfApi
    except ImportError as exc:
        raise RuntimeError("push_to_hub_with_qcap requires huggingface_hub (pip install qcap[hf])") from exc

    api = HfApi(token=token)
    api.upload_file(
        path_or_fileobj=str(output),
        path_in_repo=output.name,
        repo_id=repo_id,
        repo_type="model",
    )
    return output


def trainer_callback(
    *,
    signer: str,
    modelcard_path: Path | str,
    qcap_filename: str = "custody.qcap",
    weights_path: Path | str | None = None,
):
    """Return a Hugging Face TrainerCallback that seals a .qcap on each checkpoint save."""
    try:
        from transformers import TrainerCallback
    except ImportError as exc:
        raise RuntimeError("trainer_callback requires transformers (pip install qcap[hf])") from exc

    modelcard = Path(modelcard_path)

    class QcapPushToHubCallback(TrainerCallback):
        def on_save(self, args: Any, state: Any, control: Any, **kwargs: Any) -> Any:
            output_dir = Path(getattr(args, "output_dir", "."))
            seal_model_custody(
                modelcard_path=modelcard,
                out_path=output_dir / qcap_filename,
                signer=signer,
                weights_path=weights_path,
            )
            return control

    return QcapPushToHubCallback()
