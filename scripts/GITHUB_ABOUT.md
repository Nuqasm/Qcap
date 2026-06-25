# GitHub About metadata (requires Nuqasm org admin)

Run once after `gh auth login` on an account with **admin** access to `Nuqasm/Qcap`:

```bash
gh repo edit Nuqasm/Qcap \
  --description "Open, offline, tamper-evident execution provenance and chain of custody for AI — prove which model and code ran, on what hardware, under whose authorization, and what it produced. Apache-2.0. Post-quantum (ML-DSA-87) signatures." \
  --homepage "https://github.com/Nuqasm/Qcap" \
  --add-topic provenance \
  --add-topic chain-of-custody \
  --add-topic ai-safety \
  --add-topic ml-provenance \
  --add-topic supply-chain-security \
  --add-topic post-quantum-cryptography \
  --add-topic ml-dsa \
  --add-topic attestation \
  --add-topic tamper-evident \
  --add-topic model-cards \
  --add-topic agents
```

On Windows (PowerShell), use `scripts/set_github_about.ps1`.
