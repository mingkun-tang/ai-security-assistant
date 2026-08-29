# Adversarial Holdout Evaluation

Independent holdout corpus to stress-test scanner generalization **after** the frozen 60-case benchmark. Cases are not trivial renames of frozen benchmark files.

## Structure

- `ground_truth.json` — labels and explanations
- `corpus/<class>/` — Python samples (50 cases: 10 per supported class)
- `scripts/generate_holdout.py` — regenerate corpus from embedded definitions

## Run

```sh
uv run python evaluation/holdout/scripts/generate_holdout.py
uv run ai-security-assistant benchmark --benchmark-root evaluation/holdout --output-dir evaluation/results/holdout
```

Frozen benchmark (must remain 60/60):

```sh
uv run ai-security-assistant benchmark --output-dir evaluation/results
```

## Design

Each class includes obvious vulnerabilities, subtle variants, safe lookalikes, and alternate APIs/control-flow shapes (httpx, header-based SSRF, style/onclick XSS, ORM filter IDOR, etc.).

Holdout results measure generalization; frozen benchmark results measure regression on the locked Sprint 1 baseline.

## First-run baseline (before holdout tuning)

Captured against scanner at commit `fc067a1` (Scanner Quality Sprint). **Do not tune the scanner against this set** — it is now a development/diagnostic corpus after failure inspection.

| Metric | Value |
| --- | ---: |
| Total cases | 50 |
| Vulnerable / safe | 25 / 25 |
| TP / TN / FP / FN | 18 / 23 / 2 / 7 |
| Precision | 0.900 |
| Recall | 0.720 |
| F1 | 0.800 |
| Accuracy | 0.820 |

Artifacts: `evaluation/results/holdout/benchmark-results.json` and `.md`.

A new unseen holdout will be created after the Generalization Sprint for unbiased measurement.
