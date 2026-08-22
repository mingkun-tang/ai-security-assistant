"""Scan a Python project directory through the source analysis pipeline."""

from __future__ import annotations

import os
from pathlib import Path

from app.source_analysis import analyze_source

IGNORED_DIR_NAMES = {
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    "build",
    "dist",
    ".pytest_cache",
}

SEVERITY_ORDER = ("high", "medium", "low")


def discover_python_files(root: Path) -> list[Path]:
    """Return sorted Python file paths under root, skipping ignored directories."""

    root = root.resolve()
    if not root.is_dir():
        return []

    discovered: list[Path] = []
    for current_root, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(
            name for name in dirnames if name not in IGNORED_DIR_NAMES
        )
        for filename in sorted(filenames):
            if filename.endswith(".py"):
                discovered.append(Path(current_root) / filename)
    return discovered


def scan_project(root: str | Path) -> dict:
    """Analyze every Python file under root and aggregate deterministic findings."""

    project_root = Path(root).resolve()
    if not project_root.exists():
        raise FileNotFoundError(f"project path not found: {root}")
    if not project_root.is_dir():
        raise NotADirectoryError(f"project path is not a directory: {root}")

    python_files = discover_python_files(project_root)
    file_reports: list[dict] = []
    failures: list[dict] = []
    aggregated_findings: list[dict] = []

    for file_path in python_files:
        try:
            report = analyze_source(file_path)
            file_reports.append(
                {
                    "path": _display_path(file_path, project_root),
                    "vulnerability_indicated": report.get("vulnerability_indicated", False),
                    "findings_count": len(report.get("findings", [])),
                }
            )
            for finding in report.get("findings", []):
                aggregated_findings.append(
                    _normalize_finding(finding, file_path, project_root)
                )
        except OSError as exc:
            failures.append(
                {
                    "path": _display_path(file_path, project_root),
                    "error": str(exc),
                }
            )
        except Exception as exc:  # pragma: no cover - defensive per-file isolation
            failures.append(
                {
                    "path": _display_path(file_path, project_root),
                    "error": str(exc),
                }
            )

    findings_by_severity = {level: [] for level in SEVERITY_ORDER}
    for finding in aggregated_findings:
        severity = finding.get("confidence", "low")
        if severity not in findings_by_severity:
            findings_by_severity[severity] = []
        findings_by_severity[severity].append(finding)

    summary_counts = {
        level: len(findings_by_severity[level]) for level in SEVERITY_ORDER
    }
    total_findings = sum(summary_counts.values())

    return {
        "project": _project_display_path(project_root),
        "files_analyzed": len(file_reports),
        "files_failed": len(failures),
        "failures": failures,
        "file_reports": file_reports,
        "findings": aggregated_findings,
        "findings_by_severity": findings_by_severity,
        "summary": {
            **summary_counts,
            "total_findings": total_findings,
        },
    }


def _normalize_finding(finding: dict, file_path: Path, project_root: Path) -> dict:
    location = _primary_location(finding, file_path, project_root)
    return {
        "issue_type": finding.get("issue_type"),
        "display_name": finding.get("display_name"),
        "confidence": finding.get("confidence", "low"),
        "file": location["file"],
        "line": location["line"],
        "column": location.get("column"),
        "snippet": location.get("snippet"),
        "missing_control": finding.get("missing_control"),
        "impact": finding.get("impact"),
        "broken_trust": finding.get("broken_trust"),
        "recommendations": list(finding.get("recommendations") or []),
        "evidence_locations": finding.get("evidence_locations", []),
    }


def _primary_location(finding: dict, file_path: Path, project_root: Path) -> dict:
    locations = finding.get("evidence_locations", [])

    def from_item(item: dict) -> dict | None:
        loc = item.get("location") or {}
        if not loc.get("path"):
            return None
        return {
            "file": _display_path(Path(loc["path"]), project_root),
            "line": loc.get("line"),
            "column": loc.get("column"),
            "snippet": loc.get("snippet"),
        }

    # Prefer sink / non-input evidence for the caret location.
    for item in locations:
        if item.get("kind") == "input_source":
            continue
        mapped = from_item(item)
        if mapped is not None:
            return mapped

    for item in locations:
        mapped = from_item(item)
        if mapped is not None:
            return mapped

    return {
        "file": _display_path(file_path, project_root),
        "line": None,
        "column": None,
        "snippet": None,
    }


def _project_display_path(project_root: Path) -> str:
    resolved = project_root.resolve()
    cwd = Path.cwd().resolve()
    try:
        relative = resolved.relative_to(cwd)
        if relative == Path("."):
            return "."
        return f"./{relative.as_posix()}"
    except ValueError:
        return str(resolved)


def _display_path(path: Path, project_root: Path) -> str:
    resolved = path.resolve()
    root = project_root.resolve()
    if resolved == root:
        return "."
    try:
        return f"./{resolved.relative_to(root).as_posix()}"
    except ValueError:
        return str(resolved)
