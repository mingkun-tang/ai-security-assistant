"""CLI-facing fix suggestion orchestration over source analysis + AI provider."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from app.ai.fix_suggester import (
    FIX_DISCLAIMER,
    finding_context_from_report,
    suggest_fix,
)
from app.ai.provider import get_provider
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
            "suggestion": None,
            "finding": None,
            "source_snippet": None,
            "disclaimer": FIX_DISCLAIMER,
        }

    selected_provider = provider if provider is not None else get_provider()
    suggestion = suggest_fix(context, selected_provider)

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
        "reason": None if suggestion is not None else "provider_unavailable_or_invalid",
        "suggestion": suggestion,
        "finding": context["finding_snapshot"],
        "source_snippet": context.get("source_snippet") or "",
        "file": context.get("file"),
        "line": context.get("line"),
        "disclaimer": FIX_DISCLAIMER,
        "finding_unchanged": finding_snapshot_before == finding_snapshot_after,
    }
    return payload
