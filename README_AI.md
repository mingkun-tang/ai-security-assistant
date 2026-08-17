# AI Explanation Layer

## Purpose

The AI layer explains the deterministic security analysis in beginner-friendly
language. It does not classify vulnerabilities or change the deterministic
engine's findings, confidence, evidence, or vulnerability status.

The deterministic engine remains the source of truth. If the AI provider is
unavailable or returns invalid data, the deterministic CLI report still works
normally.

## OpenAI setup

1. Create an OpenAI API key in the OpenAI Platform.
2. Copy `.env.example` to a local `.env` file.
3. Set the required environment variables:

```text
OPENAI_API_KEY=your_key_here
OPENAI_MODEL=gpt-4o-mini
```

`OPENAI_MODEL` is optional. If it is not set, the application uses its
documented low-cost default model for short explanations.

Load the variables in your shell before running the CLI. For example:

```sh
set -a
source .env
set +a
uv run python app/main.py
```

Do not commit `.env` files or API keys. `.env` is ignored by Git and
`.env.example` contains placeholders only.

## Disabling AI

Leave `OPENAI_API_KEY` unset to disable AI explanations. The application then
uses `NullProvider`, which makes no network calls and leaves the deterministic
report unchanged.

## Provider behavior

When an API key is available, `OpenAIProvider` sends the immutable explanation
request to the OpenAI Responses API. The returned response must pass the local
validator before it is displayed. Invalid responses, provider errors, and
timeouts are discarded safely.

The provider interface is neutral: future providers such as Anthropic,
Gemini, Ollama, or a local model can implement the same structured
`Provider.explain(request)` contract without changing the deterministic engine
or explanation pipeline.

## Billing

OpenAI API usage is billed separately and varies by model and usage. Review
the current provider pricing before enabling AI:

https://openai.com/api/pricing/
