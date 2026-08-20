"""Optional, provider-neutral AI explanation layer."""

from app.ai.explainer import explain_structured_result, render_ai_explanation
from app.ai.provider import (
    AIExplanationRequest,
    AIExplanationResponse,
    NullProvider,
    Provider,
)

__all__ = [
    "AIExplanationRequest",
    "AIExplanationResponse",
    "NullProvider",
    "Provider",
    "explain_structured_result",
    "render_ai_explanation",
]
