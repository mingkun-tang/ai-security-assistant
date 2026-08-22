"""Project scanner tests."""

import json
from pathlib import Path

import pytest

from app.cli import build_parser, main
from app.project_scan import discover_python_files, scan_project
from app.source_analysis import analyze_source

DEMO_PROJECT = Path(__file__).parent / "fixtures" / "demo_project"


def test_discover_python_files_skips_ignored_directories():
    files = discover_python_files(DEMO_PROJECT)
    paths = {path.as_posix() for path in files}
    assert any(path.endswith("app/routes/users.py") for path in paths)
    assert any(path.endswith("app/api/fetch.py") for path in paths)
    assert any(path.endswith("safe/utils.py") for path in paths)
    assert not any(".venv" in path for path in paths)
    assert not any("__pycache__" in path for path in paths)


def test_scan_project_aggregates_findings():
    report = scan_project(DEMO_PROJECT)
    assert report["files_analyzed"] == 4
    assert report["files_failed"] == 0
    assert report["summary"]["total_findings"] >= 3
    assert report["summary"]["high"] >= 3

    issue_types = {finding["issue_type"] for finding in report["findings"]}
    assert "sql_injection" in issue_types
    assert "ssrf" in issue_types
    assert "xss" in issue_types


def test_scan_project_includes_file_and_line():
    report = scan_project(DEMO_PROJECT)
    sqli = next(
        finding for finding in report["findings"] if finding["issue_type"] == "sql_injection"
    )
    assert sqli["file"].endswith("app/routes/users.py")
    assert sqli["line"] == 5
    assert sqli["snippet"]
    assert sqli["missing_control"]
    assert sqli["recommendations"]


def test_scan_project_continues_after_file_failure(monkeypatch):
    def flaky_analyze(path):
        if str(path).endswith("users.py"):
            raise OSError("simulated read failure")
        return analyze_source(path)

    monkeypatch.setattr("app.project_scan.analyze_source", flaky_analyze)
    report = scan_project(DEMO_PROJECT)
    assert report["files_failed"] == 1
    assert report["files_analyzed"] == 3
    assert any("users.py" in item["path"] for item in report["failures"])
    assert report["summary"]["total_findings"] >= 2


def test_cli_scan_human(capsys):
    code = main(["scan", str(DEMO_PROJECT)])
    out = capsys.readouterr().out
    assert code == 0
    assert "AI Security Assistant" in out
    assert "Files analyzed: 4" in out
    assert "SQL Injection" in out
    assert "SSRF" in out
    assert "Total Findings:" in out


def test_cli_scan_json(capsys):
    code = main(["scan", str(DEMO_PROJECT), "--json"])
    captured = capsys.readouterr()
    assert code == 0
    payload = json.loads(captured.out)
    assert payload["files_analyzed"] == 4
    assert payload["summary"]["total_findings"] >= 3
    assert payload["findings_by_severity"]["high"]


def test_cli_scan_output_json(tmp_path):
    output_path = tmp_path / "report.json"
    code = main(["scan", str(DEMO_PROJECT), "--json", "--output", str(output_path)])
    assert code == 0
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert "demo_project" in payload["project"]
    assert payload["findings"]


def test_cli_scan_output_text(tmp_path):
    output_path = tmp_path / "report.txt"
    code = main(["scan", str(DEMO_PROJECT), "--output", str(output_path)])
    assert code == 0
    text = output_path.read_text(encoding="utf-8")
    assert "AI Security Assistant" in text
    assert "SQL Injection" in text


def test_cli_scan_missing_path(capsys):
    code = main(["scan", "missing-project-dir"])
    assert code == 1
    assert "not found" in capsys.readouterr().err.lower()


def test_parser_scan_flags():
    args = build_parser().parse_args(["scan", ".", "--json", "--output", "report.json"])
    assert args.command == "scan"
    assert args.path == "."
    assert args.json is True
    assert args.output == "report.json"
