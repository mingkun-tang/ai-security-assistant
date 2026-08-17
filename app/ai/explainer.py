import json


SECTION_NAMES = (
    "what_is_happening",
    "why_it_might_be_dangerous",
    "why_the_engine_concluded_this",
    "what_to_investigate_next",
    "what_to_learn",
)
FINDING_FIELDS = (
    "issue_type",
    "display_name",
    "confidence",
    "evidence",
    "missing_control",
    "broken_trust",
    "assumption",
    "impact",
    "recommendations",
    "follow_up_questions",
)


def build_explanation_request(structured_result):
    """Select immutable deterministic facts for an optional AI explainer."""

    findings = []
    for finding in structured_result.get("findings", []):
        findings.append(
            {field: finding.get(field) for field in FINDING_FIELDS}
        )

    return {
        "scenario": structured_result.get("scenario", ""),
        "primary_issue": structured_result.get("primary_issue"),
        "vulnerability_indicated": structured_result.get(
            "vulnerability_indicated", False
        ),
        "findings": findings,
        "verification_steps": structured_result.get("summary", {}).get(
            "verification_steps", []
        ),
    }


def parse_ai_response(raw_response):
    if not isinstance(raw_response, str):
        return None

    try:
        return json.loads(raw_response)
    except json.JSONDecodeError:
        return None


def valid_sections(sections):
    return (
        isinstance(sections, dict)
        and set(sections) == set(SECTION_NAMES)
        and all(isinstance(sections[name], str) for name in SECTION_NAMES)
    )


def validate_ai_output(ai_output, explanation_request):
    """Return safe AI output or None when it violates the contract."""

    if not isinstance(ai_output, dict):
        return None
    if ai_output.get("kind") != "ai_explanation":
        return None
    if ai_output.get("based_on_engine") is not True:
        return None
    if not isinstance(ai_output.get("disclaimer"), str):
        return None
    if not valid_sections(ai_output.get("sections")):
        return None

    deterministic_findings = explanation_request["findings"]
    expected_issue_types = [
        finding["issue_type"] for finding in deterministic_findings
    ]
    finding_explanations = ai_output.get("finding_explanations")
    if not isinstance(finding_explanations, list):
        return None
    if len(finding_explanations) != len(expected_issue_types):
        return None

    returned_issue_types = []
    expected_display_names = {
        finding["issue_type"]: finding["display_name"]
        for finding in deterministic_findings
    }
    for finding_explanation in finding_explanations:
        if not isinstance(finding_explanation, dict):
            return None
        if set(finding_explanation) != {
            "issue_type",
            "display_name",
            "explanation",
        }:
            return None

        issue_type = finding_explanation["issue_type"]
        if (
            not isinstance(issue_type, str)
            or finding_explanation["display_name"]
            != expected_display_names.get(issue_type)
            or not isinstance(finding_explanation["explanation"], str)
        ):
            return None
        returned_issue_types.append(issue_type)

    if returned_issue_types != expected_issue_types:
        return None
    return ai_output


def explain_structured_result(structured_result, provider):
    """Generate an optional explanation without mutating engine results."""

    explanation_request = build_explanation_request(structured_result)
    try:
        raw_response = provider.explain(explanation_request)
    except Exception:
        return None

    return validate_ai_output(
        parse_ai_response(raw_response),
        explanation_request,
    )


def render_ai_explanation(ai_explanation):
    """Print a clearly separated, optional AI-generated explanation."""

    if ai_explanation is None:
        return

    print()
    print("AI Explanation (optional)")
    print("-------------------------")
    print(ai_explanation["disclaimer"])

    labels = {
        "what_is_happening": "What is happening?",
        "why_it_might_be_dangerous": "Why might this be dangerous?",
        "why_the_engine_concluded_this": "Why did the engine reach this conclusion?",
        "what_to_investigate_next": "What should I investigate next?",
        "what_to_learn": "What should I learn from this scenario?",
    }
    for section_name in SECTION_NAMES:
        print()
        print(labels[section_name])
        print(ai_explanation["sections"][section_name])

    for finding in ai_explanation["finding_explanations"]:
        print()
        print(f"{finding['display_name']} explanation")
        print(finding["explanation"])
