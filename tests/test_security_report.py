"""Tests for security report generation."""

from datetime import datetime, timezone
from pathlib import Path

from app.cli import main
from app.reporting.model import (
    build_security_report,
    compute_security_score,
    top_risk_categories,
)
from app.reporting.render import escape_html, render_html_report, render_markdown_report
from app.reporting.service import generate_project_report

DEMO = Path(__file__).parent / "fixtures" / "demo_project"


def sample_scan(*, empty: bool = False) -> dict:
    if empty:
        return {
            "project": "./empty",
            "files_analyzed": 3,
            "files_failed": 0,
            "failures": [],
            "findings": [],
            "findings_by_severity": {"high": [], "medium": [], "low": []},
            "summary": {"high": 0, "medium": 0, "low": 0, "total_findings": 0},
        }
    findings = [
        {
            "issue_type": "sql_injection",
            "display_name": "SQL Injection",
            "confidence": "high",
            "file": "./app/users.py",
            "line": 12,
            "snippet": 'cursor.execute("SELECT " + q)',
            "missing_control": "Unsafe query construction.",
            "impact": "Data exposure possible.",
            "recommendations": ["Use parameterized queries"],
            "evidence_locations": [
                {
                    "kind": "input_source",
                    "location": {"line": 11, "snippet": 'request.args.get("q")'},
                },
                {
                    "kind": "database_query",
                    "location": {"line": 12, "snippet": 'cursor.execute("SELECT " + q)'},
                },
            ],
            "ai_fix_suggestion": {
                "summary": "Bind the parameter.",
                "replacement_code": 'cursor.execute("SELECT %s", (q,))',
                "explanation": "Keeps input out of SQL syntax.",
            },
        },
        {
            "issue_type": "ssrf",
            "display_name": "Server-Side Request Forgery (SSRF)",
            "confidence": "high",
            "file": "./app/fetch.py",
            "line": 8,
            "snippet": "requests.get(url)",
            "missing_control": "User-controlled URL.",
            "impact": "Internal service access.",
            "recommendations": ["Allowlist destinations"],
            "evidence_locations": [],
        },
        {
            "issue_type": "idor",
            "display_name": "IDOR",
            "confidence": "medium",
            "file": "./app/users.py",
            "line": 20,
            "missing_control": "Missing ownership check.",
            "impact": "Cross-user data access.",
            "recommendations": ["Verify ownership"],
            "evidence_locations": [],
        },
        {
            "issue_type": "xss",
            "display_name": "Cross-Site Scripting (XSS)",
            "confidence": "low",
            "file": "./app/views.py",
            "line": 4,
            "missing_control": "Unescaped output.",
            "impact": "Script injection in browser.",
            "recommendations": ["Escape output"],
            "evidence_locations": [],
        },
    ]
    return {
        "project": "./demo",
        "files_analyzed": 4,
        "files_failed": 0,
        "failures": [],
        "findings": findings,
        "findings_by_severity": {
            "high": [findings[0], findings[1]],
            "medium": [findings[2]],
            "low": [findings[3]],
        },
        "summary": {"high": 2, "medium": 1, "low": 1, "total_findings": 4},
    }


def test_security_score_calculation():
    assert compute_security_score({"high": 0, "medium": 0, "low": 0}) == 100
    assert compute_security_score({"high": 1, "medium": 0, "low": 0}) == 80
    assert compute_security_score({"high": 2, "medium": 1, "low": 1}) == 100 - 40 - 10 - 4
    assert compute_security_score({"high": 10, "medium": 10, "low": 10}) == 0


def test_top_risk_categories_order():
    categories = top_risk_categories(sample_scan()["findings"])
    assert categories[0]["issue_type"] in {"sql_injection", "ssrf"}
    assert categories[0]["highest_severity"] == "high"


def test_build_report_empty_scan():
    report = build_security_report(
        sample_scan(empty=True),
        project_name="empty",
        scanned_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        duration_seconds=0.12,
    )
    assert report["security_score"] == 100
    assert report["summary"]["total_findings"] == 0
    assert "No deterministic security findings" in report["executive_summary"]["overall_posture"]


def test_markdown_generation_multiple_severities():
    report = build_security_report(
        sample_scan(),
        project_name="demo",
        scanned_at=datetime(2026, 1, 2, tzinfo=timezone.utc),
        duration_seconds=1.5,
    )
    markdown = render_markdown_report(report)
    assert "# Security Report: demo" in markdown
    assert "Security score:** 46 / 100" in markdown
    assert "SQL Injection" in markdown
    assert "Server-Side Request Forgery (SSRF)" in markdown
    assert "AI Fix Suggestion" in markdown
    assert "cursor.execute" in markdown


def test_html_generation_escapes_snippets():
    scan = sample_scan()
    scan["findings"][0]["snippet"] = '<script>alert("x")</script>'
    scan["findings"][0]["evidence_locations"] = [
        {
            "kind": "database_query",
            "location": {"line": 1, "snippet": '<script>alert("x")</script>'},
        }
    ]
    report = build_security_report(scan, project_name="demo")
    html = render_html_report(report)
    assert "<!DOCTYPE html>" in html
    assert "badge high" in html
    assert "&lt;script&gt;" in html
    assert "<script>alert" not in html
    assert "Security Score" in html
    assert escape_html("<b>") == "&lt;b&gt;"


def test_html_and_markdown_include_summary_fields():
    report = build_security_report(
        sample_scan(),
        project_name="acme",
        scanned_at=datetime(2026, 8, 21, 12, 0, tzinfo=timezone.utc),
        duration_seconds=2.25,
    )
    html = render_html_report(report)
    md = render_markdown_report(report)
    for text in (html, md):
        assert "acme" in text
        assert "2026-08-21" in text
        assert "2.25" in text
        assert "Executive Summary" in text
        assert "Top Risk Categories" in text


def test_generate_project_report_from_demo():
    report, markdown = generate_project_report(
        DEMO,
        format="markdown",
        include_ai_summary=False,
    )
    assert report["files_scanned"] >= 3
    assert report["summary"]["total_findings"] >= 3
    assert report["security_score"] <= 100
    assert "Security Report" in markdown
    assert "SQL Injection" in markdown


def test_cli_report_output_file(tmp_path):
    out = tmp_path / "security-report.html"
    code = main(
        [
            "report",
            str(DEMO),
            "--html",
            "--no-ai-summary",
            "--output",
            str(out),
        ]
    )
    assert code == 0
    content = out.read_text(encoding="utf-8")
    assert content.lstrip().startswith("<!DOCTYPE html>")
    assert "Security Report" in content


def test_cli_report_markdown_stdout(capsys):
    code = main(["report", str(DEMO), "--markdown", "--no-ai-summary"])
    out = capsys.readouterr().out
    assert code == 0
    assert out.lstrip().startswith("# Security Report:")
    assert "Findings" in out
