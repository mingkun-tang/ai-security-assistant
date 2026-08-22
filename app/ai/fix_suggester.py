"""Optional AI-assisted fix suggestions. Never classifies or mutates findings."""

from __future__ import annotations

import json
from typing import Any

from app.ai.explainer import parse_ai_response
from app.ai.provider import AIUnavailableError

FIX_KIND = "ai_fix_suggestion"
FIX_DISCLAIMER = (
    "AI-generated suggestion. Review before applying. "
    "This suggestion is not guaranteed to be secure and does not change "
    "the deterministic finding."
)

FIX_SYSTEM_PROMPT = """You are an educational application-security coding assistant.

The deterministic security engine is the source of truth. The supplied issue
type, confidence, evidence, and remediation guidance are immutable facts.

You must:
- propose a safer code replacement for the provided source snippet only;
- keep the same language and stay close to the original structure;
- explain why the suggestion may reduce the reported risk;
- include cautious warnings.

You must not:
- change, rename, or invent issue types;
- change confidence values;
- invent additional findings;
- claim the fix is guaranteed secure or that exploitation is confirmed;
- claim you applied the change.

Return JSON only, using this exact shape:
{
  "kind": "ai_fix_suggestion",
  "based_on_engine": true,
  "issue_type": "must match the provided issue_type exactly",
  "summary": "short summary of the suggested change",
  "replacement_code": "proposed replacement source code",
  "explanation": "why this may help",
  "warnings": ["cautionary strings"],
  "disclaimer": "must remind the user to review before applying"
}
"""


def build_fix_prompt(fix_request: dict[str, Any]) -> str:
    return (
        "Immutable deterministic finding context for an optional fix suggestion:\n"
        f"{json.dumps(fix_request, indent=2, sort_keys=True)}"
    )


def build_fix_request(context: dict[str, Any]) -> dict[str, Any]:
    """Select minimum immutable context for an optional fix suggestion."""

    return {
        "issue_type": context.get("issue_type"),
        "display_name": context.get("display_name"),
        "confidence": context.get("confidence"),
        "language": context.get("language") or "python",
        "file": context.get("file"),
        "line": context.get("line"),
        "source_snippet": context.get("source_snippet") or "",
        "evidence": context.get("evidence") or [],
        "missing_control": context.get("missing_control") or "",
        "impact": context.get("impact") or "",
        "recommendations": list(context.get("recommendations") or []),
    }


def validate_fix_output(
    ai_output: Any,
    fix_request: dict[str, Any],
) -> dict[str, Any] | None:
    """Return a safe fix suggestion or None when the contract is violated."""

    if not isinstance(ai_output, dict):
        return None
    if ai_output.get("kind") != FIX_KIND:
        return None
    if ai_output.get("based_on_engine") is not True:
        return None

    expected_issue = fix_request.get("issue_type")
    if ai_output.get("issue_type") != expected_issue:
        return None

    # AI must not attempt to override confidence if it includes the field.
    if "confidence" in ai_output and ai_output.get("confidence") != fix_request.get(
        "confidence"
    ):
        return None

    if not isinstance(ai_output.get("summary"), str) or not ai_output["summary"].strip():
        return None
    if (
        not isinstance(ai_output.get("replacement_code"), str)
        or not ai_output["replacement_code"].strip()
    ):
        return None
    if (
        not isinstance(ai_output.get("explanation"), str)
        or not ai_output["explanation"].strip()
    ):
        return None
    if not isinstance(ai_output.get("disclaimer"), str) or not ai_output[
        "disclaimer"
    ].strip():
        return None

    warnings = ai_output.get("warnings")
    if not isinstance(warnings, list) or not all(
        isinstance(item, str) for item in warnings
    ):
        return None

    # Reject payloads that try to invent findings or mutate engine fields.
    forbidden = {
        "findings",
        "primary_issue",
        "vulnerability_indicated",
        "issue_types",
        "new_findings",
    }
    if forbidden.intersection(ai_output):
        return None

    return {
        "kind": FIX_KIND,
        "based_on_engine": True,
        "issue_type": expected_issue,
        "summary": ai_output["summary"].strip(),
        "replacement_code": ai_output["replacement_code"].strip(),
        "explanation": ai_output["explanation"].strip(),
        "warnings": [item.strip() for item in warnings if item.strip()],
        "disclaimer": ai_output["disclaimer"].strip() or FIX_DISCLAIMER,
    }


def suggest_fix(context: dict[str, Any], provider) -> dict[str, Any] | None:
    """Generate an optional fix suggestion without mutating engine findings."""

    fix_request = build_fix_request(context)
    try:
        raw_response = provider.suggest_fix(fix_request)
    except AIUnavailableError:
        return None
    except Exception:
        return None

    return validate_fix_output(parse_ai_response(raw_response), fix_request)


def finding_context_from_report(
    report: dict[str, Any],
    *,
    issue_type: str,
    line: int | None = None,
) -> dict[str, Any] | None:
    """Pick an immutable finding context from a source analysis report."""

    findings = list(report.get("findings") or [])
    matches = [f for f in findings if f.get("issue_type") == issue_type]
    if not matches:
        return None

    selected = matches[0]
    if line is not None:
        for finding in matches:
            locations = finding.get("evidence_locations") or []
            finding_line = finding.get("line")
            if finding_line == line:
                selected = finding
                break
            for item in locations:
                loc = (item or {}).get("location") or {}
                if loc.get("line") == line and item.get("kind") != "input_source":
                    selected = finding
                    break

    source_snippet = selected.get("snippet") or ""
    resolved_line = selected.get("line")
    if resolved_line is None and line is not None:
        resolved_line = line

    if not source_snippet or resolved_line is None:
        for item in selected.get("evidence_locations") or []:
            if item.get("kind") == "input_source":
                continue
            loc = (item or {}).get("location") or {}
            if not source_snippet and loc.get("snippet"):
                source_snippet = loc["snippet"]
            if resolved_line is None and loc.get("line") is not None:
                resolved_line = loc.get("line")
            if source_snippet and resolved_line is not None:
                break

    if not source_snippet:
        for item in selected.get("evidence_locations") or []:
            loc = (item or {}).get("location") or {}
            if loc.get("snippet"):
                source_snippet = loc["snippet"]
                if resolved_line is None:
                    resolved_line = loc.get("line")
                break

    evidence = []
    for item in selected.get("evidence_locations") or []:
        loc = (item or {}).get("location") or {}
        evidence.append(
            {
                "kind": item.get("kind"),
                "snippet": loc.get("snippet"),
                "line": loc.get("line"),
                "attrs": item.get("attrs") or {},
            }
        )

    source = report.get("source") or {}
    return {
        "issue_type": selected.get("issue_type"),
        "display_name": selected.get("display_name"),
        "confidence": selected.get("confidence"),
        "language": source.get("language") or "python",
        "file": source.get("path") or selected.get("file"),
        "line": resolved_line,
        "source_snippet": source_snippet,
        "evidence": evidence,
        "missing_control": selected.get("missing_control") or "",
        "impact": selected.get("impact") or "",
        "recommendations": list(selected.get("recommendations") or []),
        "finding_snapshot": {
            "issue_type": selected.get("issue_type"),
            "display_name": selected.get("display_name"),
            "confidence": selected.get("confidence"),
            "missing_control": selected.get("missing_control"),
            "impact": selected.get("impact"),
            "recommendations": list(selected.get("recommendations") or []),
        },
    }
