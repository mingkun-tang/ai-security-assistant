# Unseen Holdout #2 (generalization measurement)

Independent 100-case corpus for **unbiased** evaluation after the Generalization Sprint checkpoint (`fff7b3b`).

**Rules:**
- Ground truth is locked before first scanner run.
- Do not tune scanner against this set.
- Do not modify ground truth after results.
- Do not overwrite the official first-pass result artifacts.
- Historical baselines remain in `evaluation/holdout/` (diagnostic) and `evaluation/benchmark/` (frozen).

## Structure

- `ground_truth.json` — locked labels (checksum recorded before first evaluation)
- `corpus/<class>/` — 100 Python samples (20 per class: 10 vulnerable + 10 safe)
- `scripts/generate_holdout2.py` — corpus generator
- `scripts/build_corpus_cases_rest.py` — XSS/SSRF/upload/IDOR case definitions

## Official first-pass (frozen)

- **Checkpoint:** `fff7b3b` (`feat(scanner): add lightweight taint propagation`)
- **Ground-truth SHA-256:** `f5dfa3aaee3ee0bc724f45ede88065db820b32a2c7bdf4ec2c5543f50b64f476`
- **Results:** `evaluation/results/holdout2-first-pass/`
- **Strict overall:** TP 39, TN 42, FP 8, FN 11 — Precision 0.830, Recall 0.780, F1 0.804, Accuracy 0.810, FPR 0.160
- **Category-aware overall:** identical (no cross-class noise)

This first-pass measurement is permanently frozen. Re-running Holdout #2 is measurement-only and must not overwrite these artifacts without an explicit new evaluation protocol.

## Run (measurement only)

```sh
uv run python evaluation/holdout2/scripts/generate_holdout2.py
shasum -a 256 evaluation/holdout2/ground_truth.json
uv run ai-security-assistant benchmark --benchmark-root evaluation/holdout2 --output-dir evaluation/results/holdout2-<label>
```

Do not overwrite `evaluation/results/holdout2-first-pass/`.
