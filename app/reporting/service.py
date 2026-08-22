"""Orchestrate project scan → security report rendering."""

from __future__ import annotations

import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.ai.provider import AIUnavailableError, get_provider
from app.project_scan import scan_project
from app.reporting.model import build_security_report
from app.reporting.render import render_html_report, render_markdown_report


def optional_ai_executive_summary(report: dict[str, Any], provider=None) -> str | None:
    """Ask the AI provider for a short executive narrative. Never classifies findings."""

    selected = provider if provider is not None else get_provider()
    request = {
        "kind": "ai_executive_summary_request",
        "project_name": report.get("project_name"),
        "security_score": report.get("security_score"),
        "summary": report.get("summary"),
        "top_risk_categories": report.get("top_risk_categories"),
        "executive_summary": report.get("executive_summary"),
        "instruction": (
            "Write a brief executive narrative based only on the supplied "
            "deterministic summary. Do not invent findings or change severities."
        ),
    }
    try:
        # Reuse explain() transport with a compact request payload.
        raw = selected.explain(request)
    except AIUnavailableError:
        return None
    except Exception:
        return None

    if not isinstance(raw, str) or not raw.strip():
        return None
    text = raw.strip()
    # If the provider returned JSON explanation, keep it out of the report body.
    if text.startswith("{") and text.endswith("}"):
        return None
    return text[:4000]


def generate_project_report(
    path: str | Path,
    *,
    format: str = "markdown",
    include_ai_summary: bool = True,
    provider=None,
) -> tuple[dict[str, Any], str]:
    """Scan a project and return (report_model, rendered_text)."""

    project_path = Path(path)
    started = time.perf_counter()
    scan_result = scan_project(project_path)
    duration = time.perf_counter() - started

    report = build_security_report(
        scan_result,
        project_name=project_path.resolve().name,
        scanned_at=datetime.now(timezone.utc),
        duration_seconds=duration,
    )

    if include_ai_summary:
        ai_summary = optional_ai_executive_summary(report, provider=provider)
        if ai_summary:
            report["ai_executive_summary"] = ai_summary

    fmt = format.lower().strip()
    if fmt == "html":
        rendered = render_html_report(report)
    else:
        rendered = render_markdown_report(report)
    return report, rendered
