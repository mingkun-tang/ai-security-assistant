# AI Explanation Layer

## Purpose

The AI layer explains the deterministic security analysis in beginner-friendly
language. It does not classify vulnerabilities or change the deterministic
engine's findings, confidence, evidence, or vulnerability status.

The deterministic engine remains the source of truth. If the AI provider is
unavailable or returns invalid data, the deterministic CLI report still works
normally.

## AI is optional

- **No API key required** for scanning, reporting, or the VS Code extension's deterministic findings.
- Leave `OPENAI_API_KEY` unset to disable AI entirely. The app uses `NullProvider`, makes no network calls, and leaves deterministic output unchanged.
- **You provide your own OpenAI API key** when you want explanations or fix suggestions. Usage is billed to your OpenAI account.

## OpenAI setup

1. Create an OpenAI API key in the OpenAI Platform.
2. Copy `.env.example` to a local `.env` file.
3. Set the required environment variables:

```text
OPENAI_API_KEY=your_key_here
OPENAI_MODEL=gpt-4o-mini
```

`OPENAI_MODEL` is optional. If it is not set, the application uses
`gpt-4o-mini` as the default for short explanations and fix suggestions.

In VS Code, you can also set **AI Security Assistant: Openai Model**
(`aiSecurityAssistant.openaiModel`, default `gpt-4o-mini`). The extension
forwards it to the CLI as `OPENAI_MODEL` when that variable is not already set
in your environment.

Load the variables in your shell before running the CLI. For example:

```sh
set -a
source .env
set +a
uv run ai-security-assistant analyze
```

Do not commit `.env` files or API keys. `.env` is ignored by Git and
`.env.example` contains placeholders only.

## What data is sent to the AI provider

AI requests are intentionally small:

- **Explanations:** immutable deterministic finding fields (issue type, confidence, evidence snippets, remediation text) for the analyzed scenario or file — not the whole repo.
- **Fix suggestions:** one finding's metadata plus the matched **source snippet** and evidence locations — not the full file when a snippet is available, and never the entire project tree.

The engine classifies findings locally; the AI only explains or proposes a replacement for review.

## Disabling AI

Leave `OPENAI_API_KEY` unset to disable AI explanations and fix suggestions.
Deterministic scan, report, and VS Code diagnostics continue to work.

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
