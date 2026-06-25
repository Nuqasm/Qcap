# Example: execution receipt (#07)

Seals an inference-run record that binds the output to a specific model, code
path, and authorization scope — a receipt a third party can verify offline
before trusting the decision. The `hardware_attestation` field is left null in
the open core; the commercial runtime fills it.

```bash
bash run.sh
```
