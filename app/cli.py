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

    parser.print_help()
    return 0


def run(argv: list[str] | None = None) -> None:
    raise SystemExit(main(argv))


if __name__ == "__main__":
    run(sys.argv[1:])
