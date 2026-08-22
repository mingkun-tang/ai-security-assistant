from openai import OpenAI

from app.ai.fix_suggester import FIX_SYSTEM_PROMPT, build_fix_prompt
from app.ai.prompts import SYSTEM_PROMPT, build_prompt
from app.ai.provider import (
    AIExplanationRequest,
    AIExplanationResponse,
    AIFixRequest,
    AIFixResponse,
)


DEFAULT_MODEL = "gpt-4o-mini"


class OpenAIProvider:
    """OpenAI implementation of the provider-neutral assistance interface."""

    def __init__(self, api_key, model=None, client=None):
        self.model = model or DEFAULT_MODEL
        self.client = client or OpenAI(api_key=api_key)

    def explain(self, request: AIExplanationRequest) -> AIExplanationResponse:
        response = self.client.responses.create(
            model=self.model,
            instructions=SYSTEM_PROMPT,
            input=build_prompt(request),
            text={"format": {"type": "json_object"}},
            store=False,
        )
        return response.output_text

    def suggest_fix(self, request: AIFixRequest) -> AIFixResponse:
        response = self.client.responses.create(
            model=self.model,
            instructions=FIX_SYSTEM_PROMPT,
            input=build_fix_prompt(request),
            text={"format": {"type": "json_object"}},
            store=False,
        )
        return response.output_text
