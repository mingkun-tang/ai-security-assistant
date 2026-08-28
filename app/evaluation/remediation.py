"""Remediation evaluation interfaces (stage 2 — not run at scale in Sprint 1)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol


@dataclass(frozen=True)
class RemediationCase:
    """Minimal optional smoke case for future detect → fix → rescan evaluation."""

    case_id: str
    source_path: str
    issue_type: str
    explanation: str


# Tiny optional subset for manual / paid-API smoke tests only.
REMEDIATION_SMOKE_CASES: tuple[RemediationCase, ...] = (
    RemediationCase(
        case_id="sqli-vuln-01",
        source_path="corpus/sql_injection/vuln_concat_execute.py",
        issue_type="sql_injection",
        explanation="Concatenated user input in execute() should be fixable and clear on rescan.",
    ),
)


class RemediationEvaluator(Protocol):
    """Future: measure vulnerable sample → fix → apply → rescan → gone."""

    def evaluate_case(self, case: RemediationCase) -> dict[str, Any]:
        """Return structured remediation outcome for one benchmark case."""


class StubRemediationEvaluator:
    """Placeholder evaluator — does not call OpenAI or apply fixes."""

    def evaluate_case(self, case: RemediationCase) -> dict[str, Any]:
        return {
            "case_id": case.case_id,
            "status": "not_run",
            "message": (
                "Remediation evaluation is not executed in Sprint 1. "
                "Use this interface for future detect → suggest → apply → rescan runs."
            ),
        }
