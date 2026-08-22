"""Tests for optional AI fix suggestions."""

import copy
import json

from app.ai.fix_suggester import (
    FIX_KIND,
    build_fix_request,
    finding_context_from_report,
    suggest_fix,
    validate_fix_output,
)
from app.ai.provider import AIUnavailableError, NullProvider
from app.cli import main
from app.fix_suggestion import suggest_fix_for_file
from app.source_analysis import analyze_source
from pathlib import Path

FIXTURES = Path(__file__).parent / "fixtures"


class FakeFixProvider:
    def __init__(self, response):
        self.response = response
        self.request = None

    def explain(self, request):
        raise AssertionError("explain should not be called for fix suggestions")

    def suggest_fix(self, request):
        self.request = request
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


def valid_fix_response(issue_type="sql_injection"):
    return {
        "kind": FIX_KIND,
        "based_on_engine": True,
        "issue_type": issue_type,
        "summary": "Bind the user id as a query parameter.",
        "replacement_code": (
            'cursor.execute(\n'
            '    "SELECT * FROM users WHERE id = %s",\n'
            "    (user_id,),\n"
            ")"
        ),
        "explanation": (
            "Parameter binding keeps user input out of SQL syntax."
        ),
        "warnings": [
            "Review before applying. This is not guaranteed to be secure."
        ],
        "disclaimer": (
            "AI-generated suggestion. Review before applying."
        ),
    }


def sqli_context():
    report = analyze_source(FIXTURES / "sqli_vulnerable.py")
    context = finding_context_from_report(report, issue_type="sql_injection")
    assert context is not None
    return report, context


def test_build_fix_request_contains_only_immutable_context():
    _, context = sqli_context()
    request = build_fix_request(context)
    assert request["issue_type"] == "sql_injection"
    assert request["confidence"] == "high"
    assert "source_snippet" in request
    assert "recommendations" in request
    assert "vulnerability_indicated" not in request


def test_valid_structured_fix_response_is_accepted():
    _, context = sqli_context()
    request = build_fix_request(context)
    validated = validate_fix_output(valid_fix_response(), request)
    assert validated is not None
    assert validated["issue_type"] == "sql_injection"
    assert "cursor.execute" in validated["replacement_code"]


def test_malformed_fix_response_is_rejected():
    _, context = sqli_context()
    request = build_fix_request(context)
    assert validate_fix_output({"kind": "nope"}, request) is None
    assert validate_fix_output("not-json-object", request) is None
    assert (
        validate_fix_output(
            {**valid_fix_response(), "replacement_code": ""},
            request,
        )
        is None
    )


def test_issue_type_cannot_be_changed_by_ai():
    _, context = sqli_context()
    request = build_fix_request(context)
    mutated = valid_fix_response()
    mutated["issue_type"] = "xss"
    assert validate_fix_output(mutated, request) is None


def test_confidence_override_is_rejected():
    _, context = sqli_context()
    request = build_fix_request(context)
    mutated = valid_fix_response()
    mutated["confidence"] = "low"
    assert validate_fix_output(mutated, request) is None


def test_invented_findings_are_rejected():
    _, context = sqli_context()
    request = build_fix_request(context)
    mutated = valid_fix_response()
    mutated["findings"] = [{"issue_type": "ssrf"}]
    assert validate_fix_output(mutated, request) is None


def test_deterministic_finding_remains_unchanged():
    report, context = sqli_context()
    original = copy.deepcopy(report)
    provider = FakeFixProvider(json.dumps(valid_fix_response()))
    suggestion = suggest_fix(context, provider)
    assert suggestion is not None
    assert report == original
    assert suggestion["issue_type"] == context["issue_type"]


def test_no_key_fallback_returns_unavailable():
    report = analyze_source(FIXTURES / "sqli_vulnerable.py")
    original = copy.deepcopy(report)
    payload = suggest_fix_for_file(
        FIXTURES / "sqli_vulnerable.py",
        issue_type="sql_injection",
        provider=NullProvider(),
    )
    assert payload["available"] is False
    assert payload["message"] == "AI fix suggestion unavailable."
    assert payload["suggestion"] is None
    assert payload["finding"]["issue_type"] == "sql_injection"
    assert report == original


def test_provider_error_fallback():
    _, context = sqli_context()
    suggestion = suggest_fix(
        context,
        FakeFixProvider(AIUnavailableError("no key")),
    )
    assert suggestion is None


def test_cli_suggest_fix_json_without_key(capsys, monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    path = FIXTURES / "sqli_vulnerable.py"
    code = main(
        [
            "suggest-fix",
            str(path),
            "--issue",
            "sql_injection",
            "--json",
        ]
    )
    captured = capsys.readouterr()
    assert code == 0
    payload = json.loads(captured.out)
    assert payload["available"] is False
    assert payload["message"] == "AI fix suggestion unavailable."
    assert payload["finding"]["issue_type"] == "sql_injection"
    assert payload["finding_unchanged"] is True


def test_cli_suggest_fix_with_fake_provider(monkeypatch, capsys):
    path = FIXTURES / "sqli_vulnerable.py"

    def fake_get_provider():
        return FakeFixProvider(json.dumps(valid_fix_response()))

    monkeypatch.setattr("app.fix_suggestion.get_provider", fake_get_provider)
    code = main(
        [
            "suggest-fix",
            str(path),
            "--issue",
            "sql_injection",
            "--line",
            "5",
            "--json",
        ]
    )
    payload = json.loads(capsys.readouterr().out)
    assert code == 0
    assert payload["available"] is True
    assert "parameter" in payload["suggestion"]["replacement_code"].lower() or "%s" in payload["suggestion"]["replacement_code"]
    assert payload["finding"]["confidence"] == "high"
