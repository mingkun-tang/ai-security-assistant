# Unseen Holdout #4 (final blind generalization measurement)

Independent **100-case** corpus for the final unbiased scanner evaluation before the V1 release gate.

**Frozen scanner checkpoint:** `763cb97` (`feat(scanner): strengthen generalized security analysis`)

**Rules:**
- Ground truth locked before first scanner run.
- Do not tune scanner against this set.
- Do not modify ground truth after results.
- Do not overwrite official first-pass artifacts.
- Prior sets: `evaluation/benchmark/`, `evaluation/holdout/`, `evaluation/holdout2/`, `evaluation/holdout3/`.

## Structure

- `ground_truth.json` — locked labels
- `corpus/<class>/` — 100 Python samples (20 per class: 10 vulnerable + 10 safe)
- `scripts/generate_holdout4.py` — generator

## Official first-pass

- Results: `evaluation/results/holdout4-first-pass/`

## Official first-pass lock

- **Checkpoint:** `763cb97`
- **Ground-truth SHA-256:** `ecbfb4387b5f998eddcbdbfe0a43dec4cf53e4343e5f62055cc96e5e06cc8e10`
