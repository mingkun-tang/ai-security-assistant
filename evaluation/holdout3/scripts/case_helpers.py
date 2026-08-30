"""Shared helpers for Holdout #3 case registration."""

from __future__ import annotations

import textwrap


def add(cases: list[dict], cat: str, id: str, vuln: bool, src: str, exp: str) -> None:
    cases.append(
        {
            "id": id,
            "path": f"corpus/{cat}/{id}.py",
            "category": cat,
            "expected_vulnerable": vuln,
            "expected_issue_type": cat if vuln else None,
            "explanation": exp,
            "source": textwrap.dedent(src).strip() + "\n",
        }
    )
