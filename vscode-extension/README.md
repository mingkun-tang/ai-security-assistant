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
```

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

## Configure the CLI executable

Settings → search **AI Security Assistant**:

| Setting | Default | Purpose |
|---------|---------|---------|
| `aiSecurityAssistant.executablePath` | `ai-security-assistant` | CLI command or absolute path |
| `aiSecurityAssistant.scanOnSave` | `false` | Scan the active Python file on save |

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

1. **Problems panel** — each finding is a diagnostic on the source line (Error/Warning/Info by confidence).
2. **AI Security Assistant sidebar** — findings grouped by file; click a finding to jump to the line.
3. **Status bar** — `Security: N findings`; click to focus the sidebar.

Diagnostic text includes issue name, confidence, concise explanation, and the first remediation tip when present.

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
