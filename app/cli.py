"""Minimal CLI for AI Security Assistant."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from app import __version__
from app.ai.explainer import explain_structured_result, render_ai_explanation
from app.ai.provider import get_provider
from app.engine import analyze_scenario, render_structured_report
from app.project_scan import scan_project
from app.project_report import format_project_report, render_project_report
from app.source_analysis import analyze_source
from app.source_report import render_source_report
from app.fix_suggestion import suggest_fix_for_file
from app.reporting.service import generate_project_report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ai-security-assistant",
        description=(
            "Educational security scenario analyzer. "
            "The deterministic engine is the source of truth; "
            "AI explanation is optional and separate."
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    subparsers = parser.add_subparsers(dest="command")
    analyze_parser = subparsers.add_parser(
        "analyze",
        help="Analyze an interactive security scenario",
    )
    analyze_parser.add_argument(
        "--json",
        action="store_true",
        help=(
            "Print the deterministic structured result as machine-readable JSON. "
            "Does not include AI explanation."
        ),
    )

    analyze_file_parser = subparsers.add_parser(
        "analyze-file",
        help="Analyze a Python source file",
    )
    analyze_file_parser.add_argument(
        "path",
        help="Path to a Python source file",
    )
    analyze_file_parser.add_argument(
        "--json",
        action="store_true",
        help=(
            "Print the deterministic structured result as machine-readable JSON. "
            "Does not include AI explanation."
        ),
    )

    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan a Python project directory",
    )
    scan_parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Path to a project directory (default: current directory)",
    )
    scan_parser.add_argument(
        "--json",
        action="store_true",
        help="Print the scan result as machine-readable JSON only.",
    )
    scan_parser.add_argument(
        "--output",
        metavar="FILE",
        help="Write the scan report to a file.",
    )

    suggest_parser = subparsers.add_parser(
        "suggest-fix",
        help="Request an optional AI fix suggestion for a deterministic finding",
    )
    suggest_parser.add_argument(
        "path",
        help="Path to a Python source file",
    )
    suggest_parser.add_argument(
        "--issue",
        required=True,
        help="Deterministic issue_type to suggest a fix for (for example sql_injection)",
    )
    suggest_parser.add_argument(
        "--line",
        type=int,
        default=None,
        help="Optional 1-based line number of the finding",
    )
    suggest_parser.add_argument(
        "--json",
        action="store_true",
        help="Print the machine-readable fix-suggestion payload as JSON.",
    )

    report_parser = subparsers.add_parser(
        "report",
        help="Generate an HTML or Markdown security report for a project",
    )
    report_parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Path to a project directory (default: current directory)",
    )
    format_group = report_parser.add_mutually_exclusive_group()
    format_group.add_argument(
        "--html",
        action="store_true",
        help="Render an HTML report (default when --output ends with .html)",
    )
    format_group.add_argument(
        "--markdown",
        action="store_true",
        help="Render a Markdown report (default)",
    )
    report_parser.add_argument(
        "--output",
        metavar="FILE",
        help="Write the report to a file instead of printing to the terminal",
    )
    report_parser.add_argument(
        "--no-ai-summary",
        action="store_true",
        help="Skip the optional AI executive summary section",
    )
    return parser


def run_analyze(*, as_json: bool) -> int:
    prompt = "Enter a security scenario: "
    if as_json:
        print(prompt, end="", file=sys.stderr, flush=True)
        user_input = input()
    else:
        user_input = input(prompt)
    report = analyze_scenario(user_input)

    if as_json:
        print(json.dumps(report, indent=2, sort_keys=False))
        return 0

    render_structured_report(report)
    ai_explanation = explain_structured_result(report, get_provider())
    render_ai_explanation(ai_explanation)
    return 0


def run_analyze_file(path: str, *, as_json: bool) -> int:
    file_path = Path(path)
    if not file_path.is_file():
        print(f"error: file not found: {path}", file=sys.stderr)
        return 1

    report = analyze_source(file_path)

    if as_json:
        print(json.dumps(report, indent=2, sort_keys=False))
        return 0

    render_source_report(report)
    ai_explanation = explain_structured_result(report, get_provider())
    render_ai_explanation(ai_explanation)
    return 0


def run_scan(path: str, *, as_json: bool, output: str | None) -> int:
    project_path = Path(path)
    if not project_path.exists():
        print(f"error: project path not found: {path}", file=sys.stderr)
        return 1
    if not project_path.is_dir():
        print(f"error: project path is not a directory: {path}", file=sys.stderr)
        return 1

    report = scan_project(project_path)

    if output:
        destination = Path(output)
        if as_json:
            destination.write_text(
                json.dumps(report, indent=2, sort_keys=False) + "\n",
                encoding="utf-8",
            )
        else:
            destination.write_text(format_project_report(report), encoding="utf-8")

    if as_json:
        if not output:
            print(json.dumps(report, indent=2, sort_keys=False))
        return 0

    if not output:
        render_project_report(report)
    return 0


def run_suggest_fix(
    path: str,
    *,
    issue_type: str,
    line: int | None,
    as_json: bool,
) -> int:
    file_path = Path(path)
    if not file_path.is_file():
        print(f"error: file not found: {path}", file=sys.stderr)
        return 1

    payload = suggest_fix_for_file(
        file_path,
        issue_type=issue_type,
        line=line,
    )

    if as_json:
        print(json.dumps(payload, indent=2, sort_keys=False))
        return 0

    if not payload.get("available"):
        print(payload.get("message") or "AI fix suggestion unavailable.")
        return 0

    suggestion = payload["suggestion"]
    print()
    print("AI Fix Suggestion")
    print("-----------------")
    print(payload.get("disclaimer") or "")
    print()
    print(suggestion.get("summary", ""))
    print()
    print("Suggested replacement:")
    print()
    print(suggestion.get("replacement_code", ""))
    print()
    print("Why:")
    print(suggestion.get("explanation", ""))
    warnings = suggestion.get("warnings") or []
    if warnings:
        print()
        print("Warnings:")
        for item in warnings:
            print(f"- {item}")
    print()
    return 0


def _resolve_report_format(*, html: bool, markdown: bool, output: str | None) -> str:
    if html:
        return "html"
    if markdown:
        return "markdown"
    if output and str(output).lower().endswith((".html", ".htm")):
        return "html"
    return "markdown"


def run_report(
    path: str,
    *,
    html: bool,
    markdown: bool,
    output: str | None,
    no_ai_summary: bool,
) -> int:
    project_path = Path(path)
    if not project_path.exists():
        print(f"error: project path not found: {path}", file=sys.stderr)
        return 1
    if not project_path.is_dir():
        print(f"error: project path is not a directory: {path}", file=sys.stderr)
        return 1

    fmt = _resolve_report_format(html=html, markdown=markdown, output=output)
    _model, rendered = generate_project_report(
        project_path,
        format=fmt,
        include_ai_summary=not no_ai_summary,
    )

    if output:
        destination = Path(output)
        destination.write_text(rendered, encoding="utf-8")
        print(f"Wrote {fmt} report to {destination}", file=sys.stderr)
        return 0

    print(rendered)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        return 0

    if args.command == "analyze":
        return run_analyze(as_json=bool(args.json))

    if args.command == "analyze-file":
        return run_analyze_file(args.path, as_json=bool(args.json))

    if args.command == "scan":
        return run_scan(
            args.path,
            as_json=bool(args.json),
            output=args.output,
        )

    if args.command == "suggest-fix":
        return run_suggest_fix(
            args.path,
            issue_type=args.issue,
            line=args.line,
            as_json=bool(args.json),
        )

    if args.command == "report":
        return run_report(
            args.path,
            html=bool(args.html),
            markdown=bool(args.markdown),
            output=args.output,
            no_ai_summary=bool(args.no_ai_summary),
        )

    parser.print_help()
    return 0


def run(argv: list[str] | None = None) -> None:
    raise SystemExit(main(argv))


if __name__ == "__main__":
    run(sys.argv[1:])
