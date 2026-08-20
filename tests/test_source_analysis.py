"""End-to-end source analysis through parser, adapter, and engine."""

import json
from pathlib import Path

from app.cli import main
from app.engine import empty_signals
from app.parser.adapter import evidence_to_engine_input
from app.parser.evidence import empty_document
from app.parser.python_parser import parse
from app.source_analysis import analyze_source

FIXTURES = Path(__file__).parent / "fixtures"


def fixture(name: str) -> Path:
    return FIXTURES / name


def test_sqli_positive():
    report = analyze_source(fixture("sqli_vulnerable.py"))
    assert report["primary_issue"] == "sql_injection"
    assert report["vulnerability_indicated"] is True
    finding = report["findings"][0]
    assert finding["evidence_locations"][0]["location"]["snippet"]


def test_sqli_negative():
    report = analyze_source(fixture("sqli_safe.py"))
    assert report["vulnerability_indicated"] is False


def test_xss_positive():
    report = analyze_source(fixture("xss_vulnerable.py"))
    assert report["primary_issue"] == "xss"


def test_xss_negative():
    report = analyze_source(fixture("xss_safe.py"))
    assert report["vulnerability_indicated"] is False


def test_ssrf_positive():
    report = analyze_source(fixture("ssrf_vulnerable.py"))
    assert report["primary_issue"] == "ssrf"


def test_ssrf_negative():
    report = analyze_source(fixture("ssrf_safe.py"))
    assert report["vulnerability_indicated"] is False


def test_upload_positive():
    report = analyze_source(fixture("upload_vulnerable.py"))
    assert report["primary_issue"] == "file_upload"


def test_upload_negative():
    report = analyze_source(fixture("upload_safe.py"))
    assert report["vulnerability_indicated"] is False


def test_idor_positive():
    report = analyze_source(fixture("idor_vulnerable.py"))
    assert report["primary_issue"] == "idor"


def test_idor_negative():
    report = analyze_source(fixture("idor_safe.py"))
    assert report["vulnerability_indicated"] is False


def test_analyze_source_includes_evidence_facts():
    report = analyze_source(fixture("sqli_vulnerable.py"))
    kinds = {fact["kind"] for fact in report["evidence_facts"]}
    assert "input_source" in kinds
    assert "database_query" in kinds


def test_adapter_maps_sqli_signals():
    path = fixture("sqli_vulnerable.py")
    evidence = parse("python", str(path), path.read_text(encoding="utf-8"))
    data = evidence_to_engine_input(evidence)
    assert data["signals"]["injection"]["unsafe_query_construction"] is True
    assert data["signals"]["input"]["user_controlled_input"] is True


def test_adapter_empty_document_still_empty():
    data = evidence_to_engine_input(empty_document(language="python", path="empty.py"))
    assert data["signals"] == empty_signals()
    assert data["action"] is None


def test_cli_analyze_file_human(capsys):
    path = fixture("sqli_vulnerable.py")
    code = main(["analyze-file", str(path)])
    out = capsys.readouterr().out
    assert code == 0
    assert "SQL Injection" in out
    assert path.name in out or str(path) in out


def test_cli_analyze_file_json(capsys):
    path = fixture("ssrf_vulnerable.py")
    code = main(["analyze-file", str(path), "--json"])
    captured = capsys.readouterr()
    assert code == 0
    payload = json.loads(captured.out)
    assert payload["primary_issue"] == "ssrf"
    assert payload["source"]["path"].endswith("ssrf_vulnerable.py")
    assert payload["evidence_facts"]


def test_cli_analyze_file_missing_path(capsys):
    code = main(["analyze-file", "missing-file.py"])
    assert code == 1
    assert "not found" in capsys.readouterr().err.lower()
