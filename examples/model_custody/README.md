# Example: model custody (#06)

Seals a model card — base model, training-data manifest, fine-tune lineage, and
safety filters — into a `.qcap` receipt that answers *"exactly which model,
trained from what, changed how."*

```bash
bash run.sh
```

## Referenced weights (hash-only commitment)

Large artifacts can be committed by hash without embedding them in the capsule:

```bash
qcap seal modelcard.json --reference weights.stub --out llama-ft.qcap --signer alice
qcap verify llama-ft.qcap --reference weights.stub=weights.stub
```

## Hugging Face hook

After `push_to_hub`, emit a custody receipt:

```bash
python push_to_hub_example.py
```

See [`qcap/hf.py`](../../qcap/hf.py) for `seal_model_custody`, `push_to_hub_with_qcap`, and `trainer_callback()`.
