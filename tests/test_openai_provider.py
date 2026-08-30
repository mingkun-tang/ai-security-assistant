import json

from app.ai.openai_provider import DEFAULT_MODEL, OpenAIProvider
from app.ai.provider import NullProvider, get_provider
from app.engine import analyze_scenario


class FakeResponse:
    def __init__(self, output_text):
        self.output_text = output_text


class FakeResponsesClient:
    def __init__(self, output_text):
        self.output_text = output_text
        self.calls = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        return FakeResponse(self.output_text)


class FakeClient:
    def __init__(self, output_text):
        self.responses = FakeResponsesClient(output_text)


def explanation_request():
    report = analyze_scenario("I can view another user's data")
    return {
        "scenario": report["scenario"],
        "primary_issue": report["primary_issue"],
        "vulnerability_indicated": report["vulnerability_indicated"],
        "findings": report["findings"],
        "verification_steps": [],
    }


def test_openai_provider_uses_responses_api_with_structured_request():
    client = FakeClient('{"kind": "ai_explanation"}')
    provider = OpenAIProvider(
        api_key="test-key",
        model="test-model",
        client=client,
    )
    request = explanation_request()

    response = provider.explain(request)

    assert response == '{"kind": "ai_explanation"}'
    call = client.responses.calls[0]
    assert call["model"] == "test-model"
    assert call["store"] is False
    assert call["text"] == {"format": {"type": "json_object"}}
    assert "json" in call["input"].lower()
    assert "immutable deterministic analysis" in call["input"].lower()
    assert json.loads(call["input"].split(":\n", maxsplit=1)[1]) == request


def test_openai_fix_request_includes_json_when_using_json_object_format():
    from pathlib import Path

    from app.ai.fix_suggester import build_fix_request, finding_context_from_report
    from app.source_analysis import analyze_source

    client = FakeClient(json.dumps({
        "kind": "ai_fix_suggestion",
        "based_on_engine": True,
        "issue_type": "sql_injection",
        "summary": "Use parameters.",
        "replacement_code": "cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))",
        "explanation": "Keeps user input out of SQL syntax.",
        "warnings": ["Review before applying."],
        "disclaimer": "AI-generated suggestion. Review before applying.",
    }))
    provider = OpenAIProvider(api_key="test-key", model="test-model", client=client)
    report = analyze_source(Path("tests/fixtures/sqli_vulnerable.py"))
    context = finding_context_from_report(report, issue_type="sql_injection", line=5)
    assert context is not None
    request = build_fix_request(context)

    raw = provider.suggest_fix(request)
    assert isinstance(raw, str)
    call = client.responses.calls[0]
    assert call["text"] == {"format": {"type": "json_object"}}
    assert "json" in call["input"].lower()
    assert "json object" in call["input"].lower()
    assert json.loads(call["input"].split(":\n", maxsplit=1)[1]) == request


def test_openai_provider_uses_default_model_when_model_is_unset():
    client = FakeClient("{}")
    provider = OpenAIProvider(api_key="test-key", client=client)

    provider.explain(explanation_request())

    assert client.responses.calls[0]["model"] == DEFAULT_MODEL


def test_no_api_key_selects_null_provider(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    assert isinstance(get_provider(), NullProvider)


def test_openai_key_selects_openai_provider(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.setenv("OPENAI_MODEL", "configured-model")

    provider = get_provider()

    assert isinstance(provider, OpenAIProvider)
    assert provider.model == "configured-model"
