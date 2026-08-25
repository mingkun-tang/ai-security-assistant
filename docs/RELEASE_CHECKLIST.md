# Release checklist (v1.0)

Use this before tagging a GitHub release or publishing to marketplaces.

## Pre-flight

- [ ] Working tree clean (or only intentional release commits)
- [ ] Version bumped to `1.0.0` in `pyproject.toml` and `vscode-extension/package.json`
- [ ] `CHANGELOG.md` updated for this release
- [ ] `LICENSE` present (MIT)
- [ ] Replace `YOUR-PUBLISHER-ID` in `vscode-extension/package.json` before Marketplace publish

## Python

- [ ] `uv sync`
- [ ] `uv run pytest`
- [ ] `uv run ai-security-assistant --version` → `1.0.0` (or matching package version)
- [ ] `uv run ai-security-assistant scan tests/fixtures/demo_project`
- [ ] `uv run ai-security-assistant report tests/fixtures/demo_project --html --no-ai-summary --output /tmp/security-report.html`
- [ ] Optional: `uv build` and inspect `dist/` (do not upload to PyPI until ready)

## VS Code extension

- [ ] `cd vscode-extension && npm install && npm run compile && npm test`
- [ ] `npm run package` (produces `ai-security-assistant-1.0.0.vsix`)
- [ ] Install `.vsix` via **Extensions: Install from VSIX…** and smoke-test:
  - [ ] Scan workspace / current file
  - [ ] Findings in Problems + sidebar
  - [ ] Finding detail view
  - [ ] AI explanation / fix (if `OPENAI_API_KEY` set)
  - [ ] Apply suggested fix (review diff + confirm)
- [ ] Confirm packaged VSIX does **not** include `src/`, tests, or `node_modules/`

## Documentation

- [ ] Root `README.md` quick start works on a clean machine
- [ ] Screenshots section: replace placeholders when real UI captures are available
- [ ] Existing HTML report sample: `examples/security-report.html` / preview image
- [ ] `README_AI.md` still accurate for optional AI setup

## GitHub release

- [ ] Tag `v1.0.0` and push tag
- [ ] Create GitHub Release with CHANGELOG notes
- [ ] Attach `ai-security-assistant-1.0.0.vsix` as a release asset (optional but useful)

## Optional publishes (do not block v1.0 tag)

- [ ] **VS Code Marketplace** — set real `publisher`, `vsce login`, `vsce publish`
- [ ] **Open VSX** — optional alternate marketplace
- [ ] **PyPI** — `uv build` then `twine upload dist/*` (or Trusted Publishing)

## Explicitly out of scope for this checklist

- Changing detection / engine behavior
- Adding vulnerability classes
- Shipping a web dashboard
- Adding a GitHub Action (future roadmap)
