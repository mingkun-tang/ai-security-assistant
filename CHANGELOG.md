# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] — 2026-08-29

First **V1.0.0** release candidate of **AI Security Assistant** (documentation
and packaging; GitHub tag / marketplace publish may follow separately).

### Added

- **Deterministic security engine** — evidence-first classification; engine remains the source of truth
- **Python AST parser** — source analysis for Python files (inputs, sinks, evidence locations)
- **V1 vulnerability classes** — SQL Injection, XSS, SSRF, unsafe file upload, IDOR / access control
- **Project scanning** — recursive `scan` across a project with aggregated findings
- **CLI** — `analyze`, `analyze-file`, `scan`, `suggest-fix`, `report`
- **Optional AI explanations** — beginner-friendly explanations that never override findings
- **Optional AI fix suggestions** — reviewable replacement snippets via CLI / VS Code
- **VS Code extension** — Problems diagnostics, findings sidebar, detail view, apply suggested fix with automatic rescan
- **Security reports** — compact self-contained HTML and Markdown reports (score, overview table, collapsible/short finding details)

### Evaluation (blind holdouts)

Public generalization measurements on locked, previously unseen corpora
(scanned before scanner changes based on those results):

- **Holdout #3** (150 cases): accuracy 93.3%, precision 94.5%, recall 92.0%, F1 93.2%, FPR 5.3%
- **Holdout #4** (100 cases): accuracy 93.0%, precision 93.9%, recall 92.0%, F1 92.9%, FPR 6.0%

Development/regression benchmarks are separate and are not advertised as blind accuracy.

### Notes

- AI features require the user’s own `OPENAI_API_KEY`; without a key, deterministic analysis still works
- Default AI model is `gpt-4o-mini` (configurable via `OPENAI_MODEL` / `aiSecurityAssistant.openaiModel`)
- Finding context sent for AI explanations/fixes may leave the machine to the configured provider
- Extension packages as a `.vsix` for sideloading; Marketplace / PyPI publish are optional follow-ups
- V1 is educational lightweight static analysis — see README limitations before production reliance

[1.0.0]: https://github.com/mingkun-tang/ai-security-assistant/releases/tag/v1.0.0
