# AI Security Assistant

Educational **SAST-style** toolkit for Python: a **deterministic, evidence-first engine** finds issues from code and scenarios; optional AI **explains** and **suggests fixes** without ever overriding the engine.

| | |
| --- | --- |
| **CLI** | `scan`, `analyze-file`, `report`, `suggest-fix` |
| **VS Code** | Problems, sidebar, detail view, apply suggested fix |
| **Reports** | Compact HTML + Markdown |
| **License** | MIT |

---

## Key features

- Deterministic engine is the **source of truth**
- Python **AST** source analysis (inputs → sinks / evidence)
- Project-wide **scan** with severity summary
- Optional **AI explanations** and **fix suggestions** (review before apply)
- **VS Code extension** wired to the local CLI (no in-extension detection)
- **HTML / Markdown** security reports (score, findings table, details on demand)

## Supported vulnerability classes

| Class | Examples |
| --- | --- |
| Access control | IDOR, unauthorized modify/delete, privilege escalation |
| Injection / web | SQL Injection, XSS, SSRF, CSRF |
| Upload | Insecure file upload |
| Other | Insufficient evidence / unknown when signals are weak |

## Architecture

```text
Parser / AST  →  Evidence  →  Adapter  →  Deterministic Engine  →  Optional AI
                                                      ↑
                                         source of truth (never overridden)
```

- **Engine** classifies and scores confidence from evidence
- **AI** may explain or propose a fix; invalid/missing AI leaves deterministic output unchanged
- **VS Code** and **reports** consume CLI JSON / report models only

## Quick start

```sh
git clone https://github.com/mingkun-tang/ai-security-assistant.git
cd ai-security-assistant
uv sync
uv run ai-security-assistant --version
uv run ai-security-assistant scan tests/fixtures/demo_project
uv run ai-security-assistant report tests/fixtures/demo_project --html --no-ai-summary -o security-report.html
```

Requires **Python 3.12+** and [uv](https://docs.astral.sh/uv/) (or `pip install -e .`).

## CLI usage

```sh
ai-security-assistant analyze              # interactive scenario
ai-security-assistant analyze-file path.py # single file
ai-security-assistant scan .               # project scan
ai-security-assistant suggest-fix …       # optional AI fix (needs API key)
ai-security-assistant report . --html      # HTML report
ai-security-assistant report . --markdown  # Markdown report
```

Add `--json` where supported for machine-readable deterministic output.

## VS Code extension

1. Install the CLI (`uv sync`) so `ai-security-assistant` is available.
2. Build or install the extension:
   ```sh
   cd vscode-extension
   npm install
   npm run compile
   npm run package   # → ai-security-assistant-1.0.0.vsix
   ```
3. In VS Code: **Extensions: Install from VSIX…** and pick the `.vsix`.
4. Set `aiSecurityAssistant.executablePath` if the CLI is not on `PATH`.
5. Command Palette: **Scan Workspace** / **Scan Current File**.

Development Host: open the repo root → Run **Run AI Security Assistant Extension** (F5). See [`vscode-extension/README.md`](vscode-extension/README.md).

## AI explanations and fixes

**AI is optional.** The deterministic scanner, VS Code findings, and HTML/Markdown reports work **without any API key**.

When you enable AI:

- **You provide your own OpenAI API key** via `OPENAI_API_KEY` (see [`README_AI.md`](README_AI.md)). Usage is billed to your OpenAI account.
- **Default model:** `gpt-4o-mini` (CLI and VS Code). Override with `OPENAI_MODEL` in your environment, or `aiSecurityAssistant.openaiModel` in VS Code settings (parent env wins if already set).
- **Privacy / cost:** AI requests send only the relevant finding metadata and source **snippet** — not your entire repository or project tree.
- Explanations clarify **why** a finding matters — they do **not** change issue type or confidence.
- Fix suggestions are **proposals**; VS Code shows a diff and asks before applying.
- Without a key, scanning and reports still work; AI panels show unavailable states.

## Security reports

```sh
ai-security-assistant report . --html --no-ai-summary -o security-report.html
ai-security-assistant report . --markdown --no-ai-summary -o security-report.md
```

Reports lead with **summary + findings table**; HTML details are collapsed (`<details>`); Markdown stays short.

Sample output: [`examples/security-report.html`](examples/security-report.html), [`examples/security-report.md`](examples/security-report.md).

## Screenshots

| Surface | Status |
| --- | --- |
| HTML report | ![HTML report](examples/security-report-preview.png) |
| VS Code findings / Problems | *Placeholder — capture after Extension Host smoke test* (`docs/screenshots/vscode-findings.png`) |
| Finding detail view | *Placeholder —* `docs/screenshots/finding-detail.png` |
| AI fix suggestion | *Placeholder —* `docs/screenshots/ai-fix-suggestion.png` |
| CLI scan | *Placeholder —* `docs/screenshots/cli-scan.png` |

Do not invent screenshots; drop real PNGs into `docs/screenshots/` when available.

## Limitations

- Python-focused source analysis (scenario mode also supported via CLI)
- Heuristic / educational — **not** a substitute for a full commercial SAST or pen test
- AI quality depends on the provider; always review fixes
- Extension is not on the Marketplace until you publish (`.vsix` sideload works)
- No CI GitHub Action in v1.0

## Roadmap

- Marketplace + PyPI publish
- Real README screenshots from product UI
- Optional GitHub Action for `scan` / `report`
- Broader language support (post-v1)
- Hardening and false-positive reduction (engine changes only with explicit review)

## Development setup

```sh
uv sync
uv run pytest
cd vscode-extension && npm install && npm test && npm run package
```

Release steps: [`docs/RELEASE_CHECKLIST.md`](docs/RELEASE_CHECKLIST.md).  
Changes: [`CHANGELOG.md`](CHANGELOG.md).

## License

[MIT](LICENSE)
