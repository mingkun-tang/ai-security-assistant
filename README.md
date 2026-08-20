# AI Security Assistant

Educational CLI that analyzes security scenarios with a **deterministic evidence-first engine**, then optionally explains the result with an AI provider. The engine is always the source of truth; AI never overrides findings.

## Requirements

- Python 3.12+
- [uv](https://docs.astral.sh/uv/) (recommended) or pip

## Install from source

```sh
git clone https://github.com/mingkun-tang/ai-security-assistant.git
cd ai-security-assistant
uv sync
```

This installs the package in editable mode and exposes the `ai-security-assistant` command.

With pip (from the repo root, after creating a venv):

```sh
pip install -e .
pip install pytest
```

## Basic CLI usage

```sh
ai-security-assistant --help
ai-security-assistant --version
ai-security-assistant analyze
```

`analyze` prompts for a scenario interactively, prints the deterministic report, then optionally appends an AI explanation when configured.

Equivalent module form:

```sh
python -m app analyze
```

## Example analysis

```sh
ai-security-assistant analyze
```

When prompted:

```text
Enter a security scenario: An authenticated user changes the user_id in the URL and views another user's private profile.
```

## JSON output

For machine-readable output of the **deterministic** structured result only (no AI explanation):

```sh
ai-security-assistant analyze --json
```

## AI setup (optional)

Deterministic analysis works with no API keys. To enable optional AI explanations, see [README_AI.md](README_AI.md).

## Development

```sh
uv sync
uv run pytest
```
