import copy
import json

from app.ai.explainer import (
    build_explanation_request,
    explain_structured_result,
    validate_ai_output,
)
from app.engine import analyze_scenario


class FakeProvider:
    def __init__(self, response):
        self.response = response
        self.request = None

    def explain(self, request):
        self.request = request
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


def valid_response_for(report):
    return {
        "kind": "ai_explanation",
        "based_on_engine": True,
        "disclaimer": "AI-generated explanation based on deterministic findings.",
        "sections": {
            "what_is_happening": "The scenario is being reviewed.",
            "why_it_might_be_dangerous": "The result depends on engine evidence.",
            "why_the_engine_concluded_this": "The engine matched its evidence gate.",
            "what_to_investigate_next": "Validate the behavior in the application.",
            "what_to_learn": "Separate evidence from conclusions.",
        },
        "finding_explanations": [
            {
                "issue_type": finding["issue_type"],
                "display_name": finding["display_name"],
                "explanation": f"Explanation of {finding['display_name']}.",
            }
            for finding in report["findings"]
        ],
    }


def test_explanation_request_contains_only_engine_explanation_data():
    report = analyze_scenario("I can view another user's data")
    request = build_explanation_request(report)

    assert request["scenario"] == report["scenario"]
    assert request["primary_issue"] == "idor"
    assert request["vulnerability_indicated"] is True
    assert request["findings"][0]["issue_type"] == "idor"
    assert request["findings"][0]["evidence"] == report["findings"][0]["evidence"]
    assert "summary" not in request


def test_ai_explanation_cannot_mutate_engine_findings():
    report = analyze_scenario("I can view another user's data")
    original_report = copy.deepcopy(report)
    provider = FakeProvider(json.dumps(valid_response_for(report)))

    explanation = explain_structured_result(report, provider)

    assert explanation is not None
    assert report == original_report
    assert explanation["finding_explanations"][0]["issue_type"] == "idor"
    assert provider.request["scenario"] == report["scenario"]
    assert provider.request["findings"][0]["issue_type"] == "idor"


def test_no_finding_stays_no_finding_in_ai_output():
    report = analyze_scenario("I can view my own profile")
    provider = FakeProvider(json.dumps(valid_response_for(report)))

    explanation = explain_structured_result(report, provider)

    assert report["findings"] == []
    assert report["vulnerability_indicated"] is False
    assert explanation is not None
    assert explanation["finding_explanations"] == []


def test_multiple_findings_are_preserved_in_ai_output():
    report = analyze_scenario(
        "The search parameter is concatenated into a SQL query and user input "
        "is reflected into HTML."
    )
    provider = FakeProvider(json.dumps(valid_response_for(report)))

    explanation = explain_structured_result(report, provider)

    assert [
        finding["issue_type"] for finding in explanation["finding_explanations"]
    ] == ["sql_injection", "xss"]
    assert report["primary_issue"] == "sql_injection"


def test_invalid_output_with_invented_finding_is_rejected():
    report = analyze_scenario("I can view another user's data")
    invalid = valid_response_for(report)
    invalid["finding_explanations"][0]["issue_type"] = "invented_issue"
    provider = FakeProvider(json.dumps(invalid))

    assert explain_structured_result(report, provider) is None


def test_invalid_output_that_omits_finding_is_rejected():
    report = analyze_scenario(
        "The search parameter is concatenated into a SQL query and user input "
        "is reflected into HTML."
    )
    invalid = valid_response_for(report)
    invalid["finding_explanations"].pop()
    provider = FakeProvider(json.dumps(invalid))

    assert explain_structured_result(report, provider) is None


def test_provider_failure_falls_back_without_changing_report():
    report = analyze_scenario("I can view another user's data")
    original_report = copy.deepcopy(report)
    provider = FakeProvider(TimeoutError("provider timed out"))

    assert explain_structured_result(report, provider) is None
    assert report == original_report


def test_validator_rejects_invalid_json_shape():
    report = analyze_scenario("I can view another user's data")
    request = build_explanation_request(report)

    assert validate_ai_output({"kind": "wrong"}, request) is None
