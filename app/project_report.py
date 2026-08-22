"""Human-readable reports for project scans."""

from __future__ import annotations

import io

from app.project_scan import SEVERITY_ORDER


def _format_location(finding: dict) -> str:
    file_path = finding.get("file", "unknown")
    line = finding.get("line")
    if line is None:
        return file_path
    return f"{file_path}:{line}"


def format_project_report(report: dict) -> str:
    buffer = io.StringIO()
    _write_project_report(report, lambda line="": print(line, file=buffer))
    return buffer.getvalue()


def render_project_report(report: dict) -> None:
    _write_project_report(report, print)


def _write_project_report(report: dict, emit) -> None:
    failures = report.get("failures", [])
    findings_by_severity = report.get("findings_by_severity", {})
    summary = report.get("summary", {})
    total_findings = summary.get("total_findings", 0)

    emit()
    emit("=" * 38)
    emit("AI Security Assistant")
    emit("=" * 38)
    emit()
    emit("Project:")
    emit(report.get("project", "."))
    emit()
    emit(f"Files analyzed: {report.get('files_analyzed', 0)}")

    if failures:
        emit(f"Files failed: {report.get('files_failed', len(failures))}")

    if total_findings == 0:
        emit()
        emit("-" * 38)
        emit()
        emit("No findings.")
        if failures:
            emit()
            emit("Failed files:")
            for item in failures:
                emit(f"- {item['path']}: {item['error']}")
        emit()
        emit("-" * 38)
        emit()
        emit("Summary")
        emit()
        emit("High: 0")
        emit("Medium: 0")
        emit("Low: 0")
        emit()
        emit("Total Findings: 0")
        emit()
        return

    for severity in SEVERITY_ORDER:
        findings = findings_by_severity.get(severity, [])
        if not findings:
            continue
        emit()
        emit("-" * 38)
        emit()
        emit(f"{severity.upper()} ({len(findings)})")
        emit()
        for finding in findings:
            emit(f"• {finding.get('display_name', 'Finding')}")
            emit(f"  {_format_location(finding)}")
            emit()

    emit("-" * 38)
    emit()
    emit("Summary")
    emit()
    emit(f"High: {summary.get('high', 0)}")
    emit(f"Medium: {summary.get('medium', 0)}")
    emit(f"Low: {summary.get('low', 0)}")
    emit()
    emit(f"Total Findings: {total_findings}")

    if failures:
        emit()
        emit("Failed files:")
        for item in failures:
            emit(f"- {item['path']}: {item['error']}")
    emit()
