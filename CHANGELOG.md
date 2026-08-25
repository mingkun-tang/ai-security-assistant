# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] — 2026-08-24

First public-ready release of **AI Security Assistant**.

### Added

- **Deterministic security engine** — evidence-first classification; engine remains the source of truth
- **Python AST parser** — source analysis for Python files (inputs, sinks, evidence locations)
- **Project scanning** — recursive `scan` across a project with aggregated findings
- **CLI** — `analyze`, `analyze-file`, `scan`, `suggest-fix`, `report`
- **Optional AI explanations** — beginner-friendly explanations that never override findings
- **Optional AI fix suggestions** — reviewable replacement snippets via CLI / VS Code
- **VS Code extension** — Problems diagnostics, findings sidebar, detail view, apply suggested fix
- **Security reports** — compact self-contained HTML and Markdown reports (score, overview table, collapsible/short finding details)

### Notes

- AI features require `OPENAI_API_KEY`; without a key, deterministic analysis still works
- Extension packages as a `.vsix` for sideloading; Marketplace / PyPI publish are optional follow-ups

[1.0.0]: https://github.com/mingkun-tang/ai-security-assistant/releases/tag/v1.0.0
