# Security Evaluation Benchmark

Independent benchmark harness for measuring **current** deterministic scanner quality. This is separate from unit tests under `tests/`.

## What is measured

The benchmark runs `analyze_source` (Python AST parser + deterministic engine) on a fixed corpus with explicit ground truth. It does **not** pass expected answers into the scanner.

Metrics: TP, TN, FP, FN, precision, recall, F1, false-positive rate, accuracy, plus per-class breakdown.

## Supported classes (source analysis)

Authoritative list from the implementation:

- `sql_injection`
- `xss`
- `ssrf`
- `file_upload`
- `idor`

Scenario-only engine classes (`csrf`, `modify_data`, `delete_action`, `privilege_escalation`) are documented but not included in this corpus.

## Corpus

- `benchmark/ground_truth.json` — machine-readable expected outcomes
- `benchmark/corpus/<class>/` — Python sample files (30 vulnerable, 30 safe)

Regenerate corpus files from `scripts/generate_corpus.py` if needed.

## Run

```sh
uv run ai-security-assistant benchmark
uv run ai-security-assistant benchmark --json
uv run ai-security-assistant benchmark --output-dir evaluation/results
```

Outputs:

- `evaluation/results/benchmark-results.json`
- `evaluation/results/benchmark-results.md`

## Remediation evaluation (future)

`app/evaluation/remediation.py` defines interfaces for detect → fix → apply → rescan. Sprint 1 does not run paid AI remediation at scale.
