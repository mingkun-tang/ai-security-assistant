"""CLI-facing fix suggestion orchestration over source analysis + AI provider."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from app.ai.fix_suggester import (
    FIX_DISCLAIMER,
    attempt_suggest_fix,
    finding_context_from_report,
)
from app.ai.provider import get_provider
from app.ai.provider_errors import format_provider_diagnostic
from app.source_analysis import analyze_source


def suggest_fix_for_file(
    path: str | Path,
    *,
    issue_type: str,
    line: int | None = None,
    provider=None,
) -> dict[str, Any]:
    """Return a machine-readable fix-suggestion payload without mutating findings."""

    report = analyze_source(path)
    finding_snapshot_before = [
        {
            "issue_type": finding.get("issue_type"),
            "confidence": finding.get("confidence"),
            "display_name": finding.get("display_name"),
        }
        for finding in report.get("findings", [])
    ]

    context = finding_context_from_report(
        report,
        issue_type=issue_type,
        line=line,
    )
    if context is None:
        return {
            "available": False,
            "message": "AI fix suggestion unavailable.",
            "reason": "no_matching_finding",
            "error_type": None,
            "safe_message": "No matching deterministic finding was found for the request.",
            "suggestion": None,
            "finding": None,
            "source_snippet": None,
            "disclaimer": FIX_DISCLAIMER,
        }

    selected_provider = provider if provider is not None else get_provider()
    attempt = attempt_suggest_fix(context, selected_provider)
    suggestion = attempt.get("suggestion")

    # Deterministic report must remain unchanged by AI.
    finding_snapshot_after = [
        {
            "issue_type": finding.get("issue_type"),
            "confidence": finding.get("confidence"),
            "display_name": finding.get("display_name"),
        }
        for finding in report.get("findings", [])
    ]

    payload = {
        "available": suggestion is not None,
        "message": (
            None
            if suggestion is not None
            else "AI fix suggestion unavailable."
        ),
        "reason": None if suggestion is not None else attempt.get("reason"),
        "error_type": None if suggestion is not None else attempt.get("error_type"),
        "safe_message": (
            None if suggestion is not None else attempt.get("safe_message")
        ),
        "diagnostic": (
            None
            if suggestion is not None
            else format_provider_diagnostic(attempt)
        ),
        "suggestion": suggestion,
        "finding": context["finding_snapshot"],
        "source_snippet": context.get("source_snippet") or "",
        "file": context.get("file"),
        "line": context.get("line"),
        "disclaimer": FIX_DISCLAIMER,
        "finding_unchanged": finding_snapshot_before == finding_snapshot_after,
    }
    return payload
