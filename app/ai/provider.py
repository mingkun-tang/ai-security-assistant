import os
from typing import Any, Protocol


AIExplanationRequest = dict[str, Any]
AIExplanationResponse = str


class AIUnavailableError(Exception):
    """Raised when an optional explanation provider is unavailable."""


class Provider(Protocol):
    """Provider interface for optional natural-language explanations."""

    def explain(
        self,
        request: AIExplanationRequest,
    ) -> AIExplanationResponse:
        """Return an explanation response for immutable analysis data."""


class NullProvider:
    """Disabled-by-default provider that makes no network requests."""

    def explain(self, request: AIExplanationRequest) -> AIExplanationResponse:
        raise AIUnavailableError("No AI explanation provider is configured.")


def get_provider() -> Provider:
    """Select an optional provider without exposing provider details upstream."""

    api_key = os.environ.get("OPENAI_API_KEY")
    if api_key:
        from app.ai.openai_provider import OpenAIProvider

        return OpenAIProvider(
            api_key=api_key,
            model=os.environ.get("OPENAI_MODEL"),
        )
    return NullProvider()
