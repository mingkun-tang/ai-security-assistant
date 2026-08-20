"""Human-readable reports for source-file analysis."""

from __future__ import annotations

from app.engine import REPORT_RULE


def _title_case(value: str | None) -> str:
    if not value:
        return "Unknown"
    return str(value).replace("_", " ").title()


def render_source_report(report: dict) -> None:
    source = report.get("source", {})
    evidence = report.get("evidence", {})
    findings = report.get("findings", [])
    summary = report.get("summary", {})
    confidence = report.get("confidence", "low")

    print()
    print(REPORT_RULE)
    print("Source Security Analysis Report")
    print(REPORT_RULE)

    print()
    print("Source File")
    print("-----------")
    print(source.get("path", report.get("scenario", "")))

    if report.get("evidence_facts"):
        print()
        print("Observed Evidence")
        print("-----------------")
        for fact in report["evidence_facts"]:
            location = fact.get("location") or {}
            kind = fact.get("kind", "unknown")
            print(f"- {_title_case(kind)}")
            if location.get("path"):
                line = location.get("line")
                column = location.get("column")
                loc = f"{location['path']}:{line}:{column}"
                print(f"  at {loc}")
            if location.get("snippet"):
                print(f"  snippet: {location['snippet']}")

    print()
    print("Engine Assessment")
    print("-----------------")
    print(summary.get("title", ""))
    print()
    print(summary.get("scope_note", ""))
    print()
    print(f"Confidence: {_title_case(confidence)}")

    if not findings:
        print()
        print("Suggested Verification")
        print("----------------------")
        for step in summary.get("verification_steps", []):
            print(f"- {step}")
        print()
        print(REPORT_RULE)
        print()
        return

    print()
    print("Findings")
    print("--------")
    for index, finding in enumerate(findings, start=1):
        print(
            f"{index}. {finding['display_name']} — "
            f"{_title_case(finding.get('confidence'))}"
        )

    for index, finding in enumerate(findings, start=1):
        print()
        print(f"Finding {index}: {finding['display_name']}")
        print("-" * (10 + len(finding["display_name"])))
        print(f"Missing control: {finding.get('missing_control', '')}")
        print(f"Impact: {finding.get('impact', '')}")

        locations = finding.get("evidence_locations", [])
        if locations:
            print()
            print("Supporting evidence:")
            for item in locations:
                loc = item.get("location") or {}
                kind = item.get("kind", "observation")
                path = loc.get("path", "")
                line = loc.get("line")
                column = loc.get("column")
                where = f"{path}:{line}:{column}" if path else "unknown"
                print(f"- {_title_case(kind)} at {where}")
                if loc.get("snippet"):
                    print(f"  {loc['snippet']}")

        recommendations = finding.get("recommendations", [])
        if recommendations:
            print()
            print("Recommended remediation:")
            for item in recommendations[:3]:
                print(f"- {item}")

    print()
    print(REPORT_RULE)
    print()
