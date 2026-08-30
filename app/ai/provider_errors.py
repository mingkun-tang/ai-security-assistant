"""Sanitize and classify optional AI provider failures without leaking secrets."""

from __future__ import annotations

import re
from typing import Any

from app.ai.provider import AIUnavailableError

# Never emit raw secrets in diagnostics.
_SECRET_PATTERNS = (
    re.compile(r"sk-[A-Za-z0-9_\-*]+"),
    re.compile(r"Bearer\s+\S+", re.IGNORECASE),
    re.compile(
        r"(?i)(api[_-]?key|authorization|token)\s*[:=]\s*['\"]?([^\s'\"]+)"
    ),
)

PROVIDER_NOT_CONFIGURED = "provider_not_configured"
AUTHENTICATION_ERROR = "authentication_error"
RATE_LIMIT_OR_QUOTA = "rate_limit_or_quota"
NETWORK_ERROR = "network_error"
MODEL_OR_REQUEST_ERROR = "model_or_request_error"
INVALID_AI_RESPONSE = "invalid_ai_response"
UNKNOWN_PROVIDER_ERROR = "unknown_provider_error"


def sanitize_error_text(text: str, *, max_len: int = 300) -> str:
    """Return a truncated error string with obvious secrets removed."""

    cleaned = text or ""
    for pattern in _SECRET_PATTERNS:
        cleaned = pattern.sub("[REDACTED]", cleaned)
    cleaned = " ".join(cleaned.split())
    if len(cleaned) > max_len:
        cleaned = cleaned[: max_len - 3] + "..."
    return cleaned


def classify_provider_exception(exc: BaseException) -> dict[str, str]:
    """Map a provider exception to a stable, safe diagnostic reason."""

    error_type = type(exc).__name__
    safe_message = sanitize_error_text(str(exc))
    status = getattr(exc, "status_code", None)
    if status is None:
        status = getattr(exc, "status", None)
    code = getattr(exc, "code", None)
    code_text = str(code or "").lower()
    name_lower = error_type.lower()
    message_lower = safe_message.lower()

    if isinstance(exc, AIUnavailableError):
        return {
            "reason": PROVIDER_NOT_CONFIGURED,
            "error_type": error_type,
            "safe_message": safe_message
            or "No AI provider is configured.",
        }

    if (
        status in {401, 403}
        or code_text in {"invalid_api_key", "authentication_error"}
        or "authentication" in name_lower
        or "unauthorized" in message_lower
        or "invalid api key" in message_lower
        or "incorrect api key" in message_lower
    ):
        return {
            "reason": AUTHENTICATION_ERROR,
            "error_type": error_type,
            "safe_message": safe_message or "Authentication with the AI provider failed.",
        }

    if (
        status == 429
        or code_text in {"rate_limit_exceeded", "insufficient_quota"}
        or "ratelimit" in name_lower
        or "rate_limit" in name_lower
        or "quota" in message_lower
        or "rate limit" in message_lower
    ):
        return {
            "reason": RATE_LIMIT_OR_QUOTA,
            "error_type": error_type,
            "safe_message": safe_message
            or "AI provider rate limit or quota was exceeded.",
        }

    if (
        "connection" in name_lower
        or "timeout" in name_lower
        or "network" in name_lower
        or "connection" in message_lower
        or "timed out" in message_lower
    ):
        return {
            "reason": NETWORK_ERROR,
            "error_type": error_type,
            "safe_message": safe_message or "Network error contacting the AI provider.",
        }

    if (
        status in {400, 404, 422}
        or "badrequest" in name_lower
        or "notfound" in name_lower
        or "invalid_request" in code_text
        or "model" in message_lower
    ):
        return {
            "reason": MODEL_OR_REQUEST_ERROR,
            "error_type": error_type,
            "safe_message": safe_message
            or "The AI model or request was rejected by the provider.",
        }

    return {
        "reason": UNKNOWN_PROVIDER_ERROR,
        "error_type": error_type,
        "safe_message": safe_message or "Unexpected AI provider error.",
    }


def format_provider_diagnostic(info: dict[str, Any] | None) -> str | None:
    """Human-readable one-line diagnostic for stderr / debug."""

    if not info:
        return None
    reason = info.get("reason") or UNKNOWN_PROVIDER_ERROR
    error_type = info.get("error_type") or "Error"
    safe_message = info.get("safe_message") or ""
    if safe_message:
        return f"AI provider diagnostic: reason={reason} error_type={error_type} message={safe_message}"
    return f"AI provider diagnostic: reason={reason} error_type={error_type}"
