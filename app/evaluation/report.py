"""Human-readable benchmark report rendering."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from app.evaluation.benchmark import BenchmarkReport
from app.evaluation.metrics import format_rate


def render_benchmark_markdown(report: BenchmarkReport) -> str:
    overall = report.overall
    lines = [
        "# Security Benchmark Report",
        "",
        f"**Generated:** {report.generated_at}",
        f"**Scanner:** {report.scanner}",
        f"**Benchmark root:** `{report.benchmark_root}`",
        "",
        "## Summary",
        "",
        f"- **Total cases:** {report.total_cases}",
        f"- **Vulnerable (positive):** {report.vulnerable_cases}",
        f"- **Safe (negative):** {report.safe_cases}",
        "",
        "## Overall metrics",
        "",
        "| Metric | Value |",
        "| --- | ---: |",
        f"| TP | {overall['tp']} |",
        f"| TN | {overall['tn']} |",
        f"| FP | {overall['fp']} |",
        f"| FN | {overall['fn']} |",
        f"| Precision | {format_rate(overall.get('precision'))} |",
        f"| Recall | {format_rate(overall.get('recall'))} |",
        f"| F1 | {format_rate(overall.get('f1'))} |",
        f"| False-positive rate | {format_rate(overall.get('false_positive_rate'))} |",
        f"| Accuracy | {format_rate(overall.get('accuracy'))} |",
        "",
        "## Per-class metrics",
        "",
        "| Class | TP | TN | FP | FN | Precision | Recall | F1 | FPR |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]

    for category, metrics in sorted(report.per_class.items()):
        lines.append(
            f"| {category} | {metrics['tp']} | {metrics['tn']} | {metrics['fp']} | "
            f"{metrics['fn']} | {format_rate(metrics.get('precision'))} | "
            f"{format_rate(metrics.get('recall'))} | {format_rate(metrics.get('f1'))} | "
            f"{format_rate(metrics.get('false_positive_rate'))} |"
        )

    lines.extend(["", "## Failures (FP / FN)", ""])
    if not report.failures:
        lines.append("_No false positives or false negatives._")
    else:
        for failure in report.failures:
            lines.append(f"### {failure['case_id']} ({failure['outcome'].upper()})")
            lines.append("")
            lines.append(
                f"- **Expected vulnerable:** {failure['expected_vulnerable']}"
            )
            lines.append(
                f"- **Expected issue type:** `{failure.get('expected_issue_type')}`"
            )
            lines.append(
                f"- **Actual issue types:** `{failure.get('actual_issue_types')}`"
            )
            lines.append(f"- **Primary issue:** `{failure.get('primary_issue')}`")
            lines.append(f"- **Scanner rules/findings:** `{failure.get('scanner_rules')}`")
            lines.append("")

    lines.append(
        "_Deterministic benchmark — scanner rules were not modified for this run._"
    )
    lines.append("")
    return "\n".join(lines)


def write_benchmark_reports(
    report: BenchmarkReport,
    output_dir: Path,
    *,
    json_name: str = "benchmark-results.json",
    markdown_name: str = "benchmark-results.md",
) -> dict[str, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    from app.evaluation.benchmark import report_to_dict

    payload = report_to_dict(report)
    json_path = output_dir / json_name
    md_path = output_dir / markdown_name
    json_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    md_path.write_text(render_benchmark_markdown(report), encoding="utf-8")
    return {"json": json_path, "markdown": md_path}
