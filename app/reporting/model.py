"""Deterministic security report model built from project scan results."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SEVERITY_WEIGHT = {"high": 20, "medium": 10, "low": 4}
SEVERITY_ORDER = ("high", "medium", "low")


def compute_security_score(summary: dict[str, Any]) -> int:
    """Return a 0–100 score from finding counts. Lower findings → higher score."""

    high = int(summary.get("high") or 0)
    medium = int(summary.get("medium") or 0)
    low = int(summary.get("low") or 0)
    penalty = high * SEVERITY_WEIGHT["high"] + medium * SEVERITY_WEIGHT["medium"] + low * SEVERITY_WEIGHT["low"]
    return max(0, min(100, 100 - penalty))


def top_risk_categories(findings: list[dict[str, Any]], *, limit: int = 5) -> list[dict[str, Any]]:
    counts: Counter[str] = Counter()
    severity_rank = {"high": 3, "medium": 2, "low": 1}
    best_severity: dict[str, str] = {}

    for finding in findings:
        issue = finding.get("issue_type") or finding.get("display_name") or "unknown"
        counts[issue] += 1
        severity = str(finding.get("confidence") or "low")
        current = best_severity.get(issue, "low")
        if severity_rank.get(severity, 0) >= severity_rank.get(current, 0):
            best_severity[issue] = severity

    ranked = sorted(
        counts.items(),
        key=lambda item: (
            -severity_rank.get(best_severity.get(item[0], "low"), 0),
            -item[1],
            item[0],
        ),
    )
    result = []
    for issue_type, count in ranked[:limit]:
        result.append(
            {
                "issue_type": issue_type,
                "display_name": _display_name_for(issue_type, findings),
                "count": count,
                "highest_severity": best_severity.get(issue_type, "low"),
            }
        )
    return result


def _display_name_for(issue_type: str, findings: list[dict[str, Any]]) -> str:
    for finding in findings:
        if finding.get("issue_type") == issue_type and finding.get("display_name"):
            return str(finding["display_name"])
    return str(issue_type).replace("_", " ").title()


def highest_priority_files(findings: list[dict[str, Any]], *, limit: int = 5) -> list[dict[str, Any]]:
    severity_rank = {"high": 3, "medium": 2, "low": 1}
    by_file: dict[str, dict[str, Any]] = {}
    for finding in findings:
        path = finding.get("file") or "unknown"
        entry = by_file.setdefault(
            path,
            {"file": path, "count": 0, "highest_severity": "low", "score": 0},
        )
        severity = str(finding.get("confidence") or "low")
        entry["count"] += 1
        entry["score"] += SEVERITY_WEIGHT.get(severity, 1)
        if severity_rank.get(severity, 0) >= severity_rank.get(entry["highest_severity"], 0):
            entry["highest_severity"] = severity

    ranked = sorted(
        by_file.values(),
        key=lambda item: (-item["score"], -item["count"], item["file"]),
    )
    return ranked[:limit]


def build_executive_summary(report: dict[str, Any]) -> dict[str, str]:
    summary = report.get("summary") or {}
    findings = report.get("findings") or []
    score = report.get("security_score", compute_security_score(summary))
    total = int(summary.get("total_findings") or 0)
    high = int(summary.get("high") or 0)

    if total == 0:
        posture = (
            "No deterministic security findings were detected in the scanned Python files. "
            "This does not prove the project is free of vulnerabilities."
        )
        highest_risk = "None detected"
        priority_files = "None"
        remediation_order = (
            "Continue reviewing high-risk areas manually and re-scan after significant changes."
        )
    else:
        if score >= 80:
            posture = "Overall posture appears relatively strong, with a limited number of findings."
        elif score >= 50:
            posture = "Overall posture is mixed; several findings should be prioritized for remediation."
        else:
            posture = "Overall posture is weak relative to the number and severity of findings."

        if high:
            posture += f" {high} high-confidence finding(s) require prompt attention."

        categories = report.get("top_risk_categories") or top_risk_categories(findings)
        highest_risk = (
            categories[0]["display_name"] if categories else "Unknown"
        )
        priority = report.get("priority_files") or highest_priority_files(findings)
        priority_files = ", ".join(item["file"] for item in priority[:3]) or "Unknown"

        remediation_parts = []
        for index, category in enumerate(categories[:3], start=1):
            remediation_parts.append(
                f"{index}. Address {category['display_name']} "
                f"({category['count']} finding(s), highest severity: {category['highest_severity']})"
            )
        for index, item in enumerate(priority[:3], start=len(remediation_parts) + 1):
            remediation_parts.append(
                f"{index}. Review {item['file']} "
                f"({item['count']} finding(s), {item['highest_severity']} severity)"
            )
        remediation_order = "\n".join(remediation_parts)

    return {
        "overall_posture": posture,
        "highest_risk_type": highest_risk,
        "highest_priority_files": priority_files,
        "recommended_remediation_order": remediation_order,
    }


def build_security_report(
    scan_result: dict[str, Any],
    *,
    project_name: str | None = None,
    scanned_at: datetime | None = None,
    duration_seconds: float | None = None,
    ai_executive_summary: str | None = None,
) -> dict[str, Any]:
    """Compose a shareable report model from a project scan payload."""

    findings = list(scan_result.get("findings") or [])
    summary = dict(scan_result.get("summary") or {})
    summary.setdefault("high", 0)
    summary.setdefault("medium", 0)
    summary.setdefault("low", 0)
    summary.setdefault("total_findings", len(findings))

    score = compute_security_score(summary)
    categories = top_risk_categories(findings)
    priority_files = highest_priority_files(findings)
    when = scanned_at or datetime.now(timezone.utc)

    report = {
        "project_name": project_name
        or _project_name_from_path(scan_result.get("project") or "."),
        "project_path": scan_result.get("project") or ".",
        "scanned_at": when.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "files_scanned": int(scan_result.get("files_analyzed") or 0),
        "files_failed": int(scan_result.get("files_failed") or 0),
        "duration_seconds": round(float(duration_seconds or 0.0), 3),
        "summary": summary,
        "security_score": score,
        "top_risk_categories": categories,
        "priority_files": priority_files,
        "findings": findings,
        "findings_by_severity": scan_result.get("findings_by_severity")
        or _group_by_severity(findings),
        "failures": list(scan_result.get("failures") or []),
    }
    report["executive_summary"] = build_executive_summary(report)
    if ai_executive_summary and ai_executive_summary.strip():
        report["ai_executive_summary"] = ai_executive_summary.strip()
    else:
        report["ai_executive_summary"] = None
    return report


def _group_by_severity(findings: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    grouped = {level: [] for level in SEVERITY_ORDER}
    for finding in findings:
        severity = str(finding.get("confidence") or "low")
        grouped.setdefault(severity, []).append(finding)
    return grouped


def _project_name_from_path(path_value: str) -> str:
    path = Path(path_value)
    if path.name in {"", ".", ".."}:
        return Path.cwd().name or "project"
    return path.name or str(path_value)
