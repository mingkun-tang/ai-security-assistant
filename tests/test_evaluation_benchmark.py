"""Integration tests for benchmark harness (scanner not tuned to corpus)."""

from pathlib import Path

from app.evaluation.benchmark import (
    default_benchmark_root,
    load_ground_truth,
    run_benchmark,
    SOURCE_ANALYSIS_ISSUE_TYPES,
)
from app.evaluation.remediation import REMEDIATION_SMOKE_CASES, StubRemediationEvaluator


def test_ground_truth_loads_sixty_cases():
    root, cases = load_ground_truth()
    assert root.exists()
    assert len(cases) == 60
    assert len(SOURCE_ANALYSIS_ISSUE_TYPES) == 5
    vulnerable = sum(1 for c in cases if c.expected_vulnerable)
    safe = len(cases) - vulnerable
    assert vulnerable == 30
    assert safe == 30
    for case in cases:
        assert case.path.exists()
        assert case.category in SOURCE_ANALYSIS_ISSUE_TYPES


def test_benchmark_runner_produces_metrics():
    report = run_benchmark(default_benchmark_root())
    assert report.total_cases == 60
    assert report.overall["total"] == 60
    assert set(report.per_class.keys()) == set(SOURCE_ANALYSIS_ISSUE_TYPES)
    assert report.overall["tp"] + report.overall["fn"] == report.vulnerable_cases
    assert report.overall["tn"] + report.overall["fp"] == report.safe_cases


def test_remediation_stub_smoke_subset():
    evaluator = StubRemediationEvaluator()
    assert len(REMEDIATION_SMOKE_CASES) >= 1
    for case in REMEDIATION_SMOKE_CASES:
        result = evaluator.evaluate_case(case)
        assert result["status"] == "not_run"
        assert case.case_id in result["case_id"]


def test_cli_benchmark_json(capsys):
    from app.cli import main

    code = main(
        [
            "benchmark",
            "--json",
            "--output-dir",
            str(Path("evaluation/results/test-run")),
        ]
    )
    assert code == 0
    out = capsys.readouterr().out
    assert '"total_cases": 60' in out
    assert '"overall"' in out
