"""Tests for sanitized AI provider error classification."""

from app.ai.provider import AIUnavailableError, NullProvider
from app.ai.provider_errors import (
    AUTHENTICATION_ERROR,
    INVALID_AI_RESPONSE,
    NETWORK_ERROR,
    PROVIDER_NOT_CONFIGURED,
    RATE_LIMIT_OR_QUOTA,
    UNKNOWN_PROVIDER_ERROR,
    classify_provider_exception,
    sanitize_error_text,
)
from app.ai.fix_suggester import attempt_suggest_fix
from app.fix_suggestion import suggest_fix_for_file
from pathlib import Path
from tests.test_fix_suggestion import FakeFixProvider, sqli_context, valid_fix_response
import json

FIXTURES = Path(__file__).parent / "fixtures"


class _FakeOpenAIError(Exception):
    def __init__(self, message, *, status_code=None, code=None):
        super().__init__(message)
        self.status_code = status_code
        self.code = code


def test_sanitize_error_text_redacts_api_keys_and_bearers():
    raw = "Incorrect API key provided: sk-abcdefghijklmnopqrstuvwxyz123456. Bearer tok_secret"
    cleaned = sanitize_error_text(raw)
    assert "sk-abcdefghijklmnopqrstuvwxyz123456" not in cleaned
    assert "tok_secret" not in cleaned
    assert "[REDACTED]" in cleaned
    # OpenAI often echoes a partially masked key fragment with asterisks.
    masked = sanitize_error_text(
        "Incorrect API key provided: sk-diag-******************-key."
    )
    assert "sk-diag-" not in masked
    assert "[REDACTED]" in masked


def test_classify_no_provider_configured():
    info = classify_provider_exception(AIUnavailableError("No AI fix-suggestion provider is configured."))
    assert info["reason"] == PROVIDER_NOT_CONFIGURED
    assert info["error_type"] == "AIUnavailableError"


def test_classify_authentication_error():
    info = classify_provider_exception(
        _FakeOpenAIError(
            "Error code: 401 - Incorrect API key provided: sk-abcdefghijklmnopqrstuvwxyz",
            status_code=401,
            code="invalid_api_key",
        )
    )
    assert info["reason"] == AUTHENTICATION_ERROR
    assert "sk-abcdefghijklmnopqrstuvwxyz" not in info["safe_message"]


def test_classify_rate_limit_or_quota():
    info = classify_provider_exception(
        _FakeOpenAIError(
            "Rate limit reached for gpt-4o-mini",
            status_code=429,
            code="rate_limit_exceeded",
        )
    )
    assert info["reason"] == RATE_LIMIT_OR_QUOTA


def test_classify_generic_provider_exception():
    info = classify_provider_exception(RuntimeError("boom without secrets"))
    assert info["reason"] == UNKNOWN_PROVIDER_ERROR
    assert info["error_type"] == "RuntimeError"
    assert "boom without secrets" in info["safe_message"]


def test_classify_network_error():
    class APIConnectionError(Exception):
        pass

    info = classify_provider_exception(APIConnectionError("Connection error."))
    assert info["reason"] == NETWORK_ERROR


def test_attempt_suggest_fix_invalid_ai_response():
    _, context = sqli_context()
    attempt = attempt_suggest_fix(
        context,
        FakeFixProvider('{"kind": "not_a_fix"}'),
    )
    assert attempt["suggestion"] is None
    assert attempt["reason"] == INVALID_AI_RESPONSE


def test_attempt_suggest_fix_authentication_error():
    _, context = sqli_context()
    attempt = attempt_suggest_fix(
        context,
        FakeFixProvider(
            _FakeOpenAIError(
                "Incorrect API key provided: sk-abcdefghijklmnopqrstuvwxyz",
                status_code=401,
                code="invalid_api_key",
            )
        ),
    )
    assert attempt["suggestion"] is None
    assert attempt["reason"] == AUTHENTICATION_ERROR
    assert "sk-abcdefghijklmnopqrstuvwxyz" not in (attempt["safe_message"] or "")


def test_suggest_fix_for_file_includes_sanitized_reason_for_null_provider():
    payload = suggest_fix_for_file(
        FIXTURES / "sqli_vulnerable.py",
        issue_type="sql_injection",
        provider=NullProvider(),
    )
    assert payload["available"] is False
    assert payload["reason"] == PROVIDER_NOT_CONFIGURED
    assert payload["error_type"] == "AIUnavailableError"
    assert "diagnostic" in payload
    assert "provider_not_configured" in payload["diagnostic"]


def test_suggest_fix_for_file_success_has_no_error_fields():
    payload = suggest_fix_for_file(
        FIXTURES / "sqli_vulnerable.py",
        issue_type="sql_injection",
        line=5,
        provider=FakeFixProvider(json.dumps(valid_fix_response())),
    )
    assert payload["available"] is True
    assert payload["reason"] is None
    assert payload["error_type"] is None
    assert payload["safe_message"] is None
    assert payload["diagnostic"] is None
