"""Run deterministic source-analysis benchmark against ground truth."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.evaluation.metrics import ConfusionCounts, compute_metrics, metrics_to_dict
from app.source_analysis import analyze_source

# Authoritative issue types detectable via Python source analysis today.
SOURCE_ANALYSIS_ISSUE_TYPES: tuple[str, ...] = (
    "sql_injection",
    "xss",
    "ssrf",
    "file_upload",
    "idor",
)

# Engine supports additional scenario-only classes (not in this benchmark corpus).
SCENARIO_ONLY_ISSUE_TYPES: tuple[str, ...] = (
    "modify_data",
    "delete_action",
    "privilege_escalation",
    "csrf",
)


@dataclass
class BenchmarkCase:
    id: str
    path: Path
    language: str
    category: str
    expected_vulnerable: bool
    expected_issue_type: str | None
    explanation: str


@dataclass
class CaseOutcome:
    case_id: str
    category: str
    expected_vulnerable: bool
    expected_issue_type: str | None
    actual_issue_types: list[str]
    primary_issue: str | None
    outcome: str
    scanner_rules: list[str]


@dataclass
class BenchmarkReport:
    generated_at: str
    benchmark_root: str
    scanner: str
    total_cases: int
    vulnerable_cases: int
    safe_cases: int
    overall: dict[str, Any]
    per_class: dict[str, dict[str, Any]]
    failures: list[dict[str, Any]] = field(default_factory=list)
    case_outcomes: list[CaseOutcome] = field(default_factory=list)


def default_benchmark_root() -> Path:
    return Path(__file__).resolve().parents[2] / "evaluation" / "benchmark"


def load_ground_truth(benchmark_root: Path | None = None) -> tuple[Path, list[BenchmarkCase]]:
    root = (benchmark_root or default_benchmark_root()).resolve()
    manifest = root / "ground_truth.json"
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    cases: list[BenchmarkCase] = []
    for item in payload.get("cases", []):
        rel = item["path"]
        cases.append(
            BenchmarkCase(
                id=item["id"],
                path=(root / rel).resolve(),
                language=item.get("language", "python"),
                category=item["category"],
                expected_vulnerable=bool(item["expected_vulnerable"]),
                expected_issue_type=item.get("expected_issue_type"),
                explanation=item.get("explanation", ""),
            )
        )
    return root, cases


def scan_case(case: BenchmarkCase) -> tuple[list[str], str | None]:
    """Run current scanner on one file. Ground truth is never passed to the engine."""

    report = analyze_source(case.path)
    findings = report.get("findings") or []
    issue_types = sorted(
        {str(f.get("issue_type")) for f in findings if f.get("issue_type")}
    )
    primary = report.get("primary_issue")
    return issue_types, str(primary) if primary else None


def classify_case_outcome(
    case: BenchmarkCase,
    detected_types: list[str],
    primary_issue: str | None,
) -> CaseOutcome:
    detected_set = set(detected_types)
    expected_type = case.expected_issue_type

    if case.expected_vulnerable:
        if expected_type and expected_type in detected_set:
            outcome = "tp"
        else:
            outcome = "fn"
    else:
        if detected_set:
            outcome = "fp"
        else:
            outcome = "tn"

    rules = detected_types.copy()
    if primary_issue and primary_issue not in rules:
        rules.append(f"primary:{primary_issue}")

    return CaseOutcome(
        case_id=case.id,
        category=case.category,
        expected_vulnerable=case.expected_vulnerable,
        expected_issue_type=expected_type,
        actual_issue_types=detected_types,
        primary_issue=primary_issue,
        outcome=outcome,
        scanner_rules=rules,
    )


def aggregate_counts(outcomes: list[CaseOutcome]) -> ConfusionCounts:
    counts = ConfusionCounts()
    for item in outcomes:
        if item.outcome == "tp":
            counts.tp += 1
        elif item.outcome == "tn":
            counts.tn += 1
        elif item.outcome == "fp":
            counts.fp += 1
        elif item.outcome == "fn":
            counts.fn += 1
    return counts


def aggregate_per_class(outcomes: list[CaseOutcome]) -> dict[str, dict[str, Any]]:
    per_class: dict[str, ConfusionCounts] = {
        category: ConfusionCounts() for category in SOURCE_ANALYSIS_ISSUE_TYPES
    }
    for item in outcomes:
        bucket = per_class.setdefault(item.category, ConfusionCounts())
        if item.outcome == "tp":
            bucket.tp += 1
        elif item.outcome == "tn":
            bucket.tn += 1
        elif item.outcome == "fp":
            bucket.fp += 1
        elif item.outcome == "fn":
            bucket.fn += 1

    return {
        category: metrics_to_dict(compute_metrics(counts))
        for category, counts in per_class.items()
    }


def run_benchmark(benchmark_root: Path | None = None) -> BenchmarkReport:
    root, cases = load_ground_truth(benchmark_root)
    outcomes: list[CaseOutcome] = []

    for case in cases:
        detected, primary = scan_case(case)
        outcomes.append(classify_case_outcome(case, detected, primary))

    overall_counts = aggregate_counts(outcomes)
    overall_metrics = compute_metrics(overall_counts)

    failures: list[dict[str, Any]] = []
    for item in outcomes:
        if item.outcome in {"fp", "fn"}:
            failures.append(
                {
                    "case_id": item.case_id,
                    "category": item.category,
                    "expected_vulnerable": item.expected_vulnerable,
                    "expected_issue_type": item.expected_issue_type,
                    "actual_issue_types": item.actual_issue_types,
                    "primary_issue": item.primary_issue,
                    "outcome": item.outcome,
                    "scanner_rules": item.scanner_rules,
                }
            )

    vulnerable_cases = sum(1 for c in cases if c.expected_vulnerable)
    safe_cases = len(cases) - vulnerable_cases

    return BenchmarkReport(
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        benchmark_root=str(root),
        scanner="analyze_source (deterministic engine + Python AST parser)",
        total_cases=len(cases),
        vulnerable_cases=vulnerable_cases,
        safe_cases=safe_cases,
        overall=metrics_to_dict(overall_metrics),
        per_class=aggregate_per_class(outcomes),
        failures=failures,
        case_outcomes=outcomes,
    )


def report_to_dict(report: BenchmarkReport) -> dict[str, Any]:
    return {
        "generated_at": report.generated_at,
        "benchmark_root": report.benchmark_root,
        "scanner": report.scanner,
        "supported_source_issue_types": list(SOURCE_ANALYSIS_ISSUE_TYPES),
        "scenario_only_issue_types": list(SCENARIO_ONLY_ISSUE_TYPES),
        "total_cases": report.total_cases,
        "vulnerable_cases": report.vulnerable_cases,
        "safe_cases": report.safe_cases,
        "overall": report.overall,
        "per_class": report.per_class,
        "failures": report.failures,
        "cases": [
            {
                "case_id": item.case_id,
                "category": item.category,
                "expected_vulnerable": item.expected_vulnerable,
                "expected_issue_type": item.expected_issue_type,
                "actual_issue_types": item.actual_issue_types,
                "primary_issue": item.primary_issue,
                "outcome": item.outcome,
            }
            for item in report.case_outcomes
        ],
    }
