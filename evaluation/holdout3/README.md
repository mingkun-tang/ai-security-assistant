# Unseen Holdout #3 (blind generalization measurement)

Independent **150-case** corpus for unbiased evaluation after Architecture Sprint #2 checkpoint (`fe1cecc`).

**Rules:**
- Ground truth is locked before first scanner run.
- Do not tune scanner against this set.
- Do not modify ground truth after results.
- Do not overwrite the official first-pass result artifacts.
- Prior baselines: `evaluation/benchmark/` (frozen), `evaluation/holdout/` (diagnostic), `evaluation/holdout2/` (generalization sprint measurement).

## Structure

- `ground_truth.json` — locked labels (checksum recorded before first evaluation)
- `corpus/<class>/` — 150 Python samples (30 per class: 15 vulnerable + 15 safe)
- `scripts/generate_holdout3.py` — corpus generator

## Official first-pass (frozen after run)

- **Checkpoint:** `fe1cecc`
- **Ground-truth SHA-256:** `ce60b98985536d7b5a3d26c7630031530040052faed538b1b3d859e6c2ee53ae`
- Results: `evaluation/results/holdout3-first-pass/`
- 150 cases (75 vulnerable / 75 safe; 30 per class)
## Run (measurement only)

```sh
uv run python evaluation/holdout3/scripts/generate_holdout3.py
shasum -a 256 evaluation/holdout3/ground_truth.json
uv run ai-security-assistant benchmark --benchmark-root evaluation/holdout3 --output-dir evaluation/results/holdout3-first-pass
```

## Official first-pass metrics (locked)

- TP 69 / TN 71 / FP 4 / FN 6
- Precision 0.945 / Recall 0.920 / F1 0.932 / Accuracy 0.933 / FPR 0.053
