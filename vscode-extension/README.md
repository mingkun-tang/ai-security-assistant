# AI Security Assistant — VS Code Extension

VS Code frontend for the local **AI Security Assistant** CLI. The extension does **not** detect vulnerabilities itself. It runs the existing deterministic analyzer and displays JSON findings in Diagnostics, Problems, and a sidebar.

```
VS Code Extension
  → ai-security-assistant CLI (--json)
  → deterministic engine
  → findings in Problems + TreeView
```

## Prerequisites

1. Node.js 20+ and npm
2. The Python CLI installed and available on your `PATH` (or set a custom path in settings)

From the repository root:

```sh
uv sync
```

Confirm the CLI works:

```sh
ai-security-assistant --version
ai-security-assistant analyze-file path/to/file.py --json
ai-security-assistant scan . --json
```

## Install extension dependencies

```sh
cd vscode-extension
npm install
npm run compile
npm test
```

## Package a `.vsix` (sideload / release asset)

```sh
cd vscode-extension
npm run package
```

This runs `vsce package` and writes `ai-security-assistant-1.0.0.vsix` (version from `package.json`).

Install in VS Code / Cursor: **Extensions: Install from VSIX…**

Before Marketplace publish, replace `publisher` (`YOUR-PUBLISHER-ID`) with your real publisher id.

## Run in Extension Development Host

### From this repository (recommended)

1. Open the **repository root** in VS Code / Cursor.
2. Run `npm install` and `npm run compile` inside `vscode-extension/` once.
3. Open **Run and Debug** and choose **Run AI Security Assistant Extension**.
4. Press **F5** (or Start Debugging).

A new Extension Development Host window opens with the extension loaded.

### From the extension folder alone

1. Open `vscode-extension/` as the workspace folder.
2. `npm install && npm run compile`
3. Press **F5** with the **Run Extension** launch config.

## Configure settings

Settings → search **AI Security Assistant**:

| Setting | Default | Purpose |
|---------|---------|---------|
| `aiSecurityAssistant.executablePath` | `ai-security-assistant` | CLI command or absolute path |
| `aiSecurityAssistant.scanOnSave` | `false` | Scan the active Python file on save |
| `aiSecurityAssistant.openaiModel` | `gpt-4o-mini` | OpenAI model forwarded as `OPENAI_MODEL` when not already set in your environment |

**AI is optional.** Scanning, Problems, sidebar findings, and reports work without an API key. When you enable AI, **you provide your own `OPENAI_API_KEY`** (in your shell or IDE environment). The extension does not ship or store keys.

**Model override:** set `OPENAI_MODEL` in your environment (wins over the VS Code setting), or change `aiSecurityAssistant.openaiModel` in settings (default `gpt-4o-mini`).

**Context sent:** AI fix/explain requests send only the relevant finding metadata and source snippet to the CLI — not your entire repository.

If the CLI is not on `PATH`, set an absolute path, for example:

```json
{
  "aiSecurityAssistant.executablePath": "/Users/you/Appsec Projects/ai-security-assistant/.venv/bin/ai-security-assistant"
}
```

Or, after `uv sync` from the repo root:

```json
{
  "aiSecurityAssistant.executablePath": "${workspaceFolder}/.venv/bin/ai-security-assistant"
}
```

(`${workspaceFolder}` works in `.vscode/settings.json` when the repo root is open.)

## Commands

Open the Command Palette (`Cmd+Shift+P` / `Ctrl+Shift+P`):

- **AI Security Assistant: Scan Current File** — saves the active `.py` file, runs `analyze-file … --json`
- **AI Security Assistant: Scan Workspace** — runs `scan <workspace> --json`
- **AI Security Assistant: Clear Findings** — clears diagnostics, sidebar, and status bar

## How findings appear

1. **Problems panel** — each finding is a diagnostic on the source line (Error/Warning/Info by confidence). Hover shows Why / Fix and a prompt to open full details.
2. **AI Security Assistant sidebar** — findings grouped by file with severity icons; click a finding to jump to the line and open the detail view.
3. **Finding detail view** — issue, confidence, evidence flow, why/impact, recommended fix, and optional AI explanation (never overwrites deterministic fields).
4. **Status bar** — `Security: N findings`; click to focus the sidebar.

Diagnostic text includes issue name, confidence, concise explanation, and the first remediation tip when present.

### Detail command

- **AI Security Assistant: View Finding Details** — opens the polished detail panel (also invoked when clicking a sidebar finding).
- **AI Security Assistant: Generate Fix Suggestion** — asks the local CLI for an optional AI fix suggestion (review only until you explicitly apply).
- **AI Security Assistant: Apply Suggested Fix** — opens a diff, asks for confirmation, then replaces only the matched snippet via VS Code edits (undoable). Rescans afterward.

AI fix suggestions require the same optional API key as explanations (`OPENAI_API_KEY`). Without a key, the UI shows “AI fix suggestion unavailable.” and deterministic findings continue working. Configure the model via `aiSecurityAssistant.openaiModel` (default `gpt-4o-mini`) or `OPENAI_MODEL` in your environment.

## Tests

```sh
cd vscode-extension
npm test
```

These cover JSON parsing, grouping, labels, and severity mapping. They do not launch a full Extension Host.

## Limitations

- Python files only
- Uses the local CLI; no in-extension detection logic
- No marketplace packaging yet
- No automatic fix application
- AI explanations appear only if the CLI JSON includes them (JSON mode today is deterministic-only)
- Workspace scan paths are resolved relative to the opened folder
