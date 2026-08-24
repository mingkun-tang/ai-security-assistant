"""HTML and Markdown renderers for security reports."""

from __future__ import annotations

import html
from typing import Any

KIND_LABELS = {
    "input_source": "User Input",
    "database_query": "Database Query",
    "network_request": "Network Request",
    "rendered_output": "Rendered Output",
    "file_upload": "File Upload",
    "data_access": "Data Access",
    "authorization_check": "Authorization Check",
    "auth_context": "Auth Context",
}


def escape_html(value: Any) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def _severity_label(value: str | None) -> str:
    text = str(value or "low")
    return text[:1].upper() + text[1:]


def _title_kind(kind: str) -> str:
    if kind in KIND_LABELS:
        return KIND_LABELS[kind]
    return " ".join(part.capitalize() for part in str(kind).split("_") if part)


def _label_for_fact(item: dict[str, Any]) -> str:
    kind = str(item.get("kind") or "evidence")
    attrs = item.get("attrs") or {}
    if kind == "input_source":
        channel = str(attrs.get("channel") or "")
        name = attrs.get("name")
        if "url" in channel or name == "url":
            return "User-Controlled URL"
        if name:
            return f"User Input ({name})"
        return "User Input"
    if kind == "network_request":
        destination = str(attrs.get("destination_kind") or "")
        if destination == "from_input" or attrs.get("uses_input_source_ids"):
            return "Server Request"
    return _title_kind(kind)


def build_evidence_flow(finding: dict[str, Any]) -> list[dict[str, Any]]:
    """Build Input → Sink steps from deterministic evidence locations."""

    steps: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in finding.get("evidence_locations") or []:
        loc = item.get("location") or {}
        snippet = (loc.get("snippet") or "").strip()
        kind = str(item.get("kind") or "evidence")
        key = f"{kind}:{snippet or item.get('id') or len(steps)}"
        if key in seen:
            continue
        seen.add(key)
        steps.append(
            {
                "label": _label_for_fact(item),
                "kind": kind,
                "snippet": snippet or None,
                "line": loc.get("line"),
            }
        )

    if not steps and finding.get("snippet"):
        steps.append(
            {
                "label": "Evidence",
                "kind": "observation",
                "snippet": str(finding["snippet"]),
                "line": finding.get("line"),
            }
        )

    sources = [step for step in steps if step["kind"] in {"input_source", "auth_context"}]
    sinks = [step for step in steps if step["kind"] not in {"input_source", "auth_context"}]
    if sources and sinks:
        return sources + sinks
    return steps


def format_evidence_flow_text(steps: list[dict[str, Any]]) -> str:
    if not steps:
        return ""
    blocks: list[str] = []
    for index, step in enumerate(steps):
        blocks.append(step["label"])
        if step.get("snippet"):
            blocks.append(str(step["snippet"]))
        if index < len(steps) - 1:
            blocks.append("        ↓")
    return "\n".join(blocks)


def _finding_ai_explanation(finding: dict[str, Any]) -> str | None:
    text = finding.get("ai_explanation")
    if isinstance(text, str) and text.strip():
        return text.strip()
    ai = finding.get("ai")
    if isinstance(ai, dict):
        nested = ai.get("explanation")
        if isinstance(nested, str) and nested.strip():
            return nested.strip()
    return None


def _finding_title(finding: dict[str, Any]) -> str:
    return str(finding.get("display_name") or finding.get("issue_type") or "Finding")


def _finding_severity(finding: dict[str, Any]) -> str:
    return str(finding.get("confidence") or "low")


def _first_sentence(value: Any, *, max_len: int = 180) -> str:
    text = " ".join(str(value or "").split())
    if not text:
        return ""
    for sep in (". ", "! ", "? "):
        if sep in text:
            text = text.split(sep, 1)[0].rstrip(" .!?") + "."
            break
    return _short_text(text, max_len=max_len)


def _short_text(value: Any, *, max_len: int = 160) -> str:
    text = " ".join(str(value or "").split())
    if len(text) <= max_len:
        return text
    clipped = text[: max_len - 1].rsplit(" ", 1)[0].rstrip(".,;:")
    return (clipped or text[: max_len - 1].rstrip()) + "…"


def _remediation_items(finding: dict[str, Any], *, limit: int = 3) -> list[str]:
    items = [str(item).strip() for item in (finding.get("recommendations") or []) if str(item).strip()]
    if items:
        return items[:limit]
    return ["Review and apply the safest available control for this finding."]


def render_markdown_report(report: dict[str, Any]) -> str:
    summary = report.get("summary") or {}
    findings = report.get("findings") or []
    lines: list[str] = [
        f"# Security Report: {report.get('project_name', 'project')}",
        "",
        f"**Scan date:** {report.get('scanned_at')}  ",
        f"**Path:** `{report.get('project_path')}`",
        "",
        "# Scan Summary",
        "",
        f"**Score:** {report.get('security_score', 0)}/100 · "
        f"**Files:** {report.get('files_scanned', 0)} · "
        f"**Findings:** {summary.get('total_findings', 0)} "
        f"(H {summary.get('high', 0)} / M {summary.get('medium', 0)} / L {summary.get('low', 0)}) · "
        f"**Duration:** {report.get('duration_seconds', 0)}s",
        "",
    ]

    ai_summary = report.get("ai_executive_summary")
    if ai_summary:
        lines.extend(
            [
                f"_AI summary:_ {_short_text(ai_summary, max_len=220)}",
                "",
            ]
        )

    lines.extend(
        [
            "# Findings Overview",
            "",
            "| Severity | Issue | File | Line |",
            "| --- | --- | --- | ---: |",
        ]
    )
    if not findings:
        lines.append("| — | _No findings detected._ | — | — |")
    else:
        for finding in findings:
            severity = _severity_label(_finding_severity(finding))
            issue = _finding_title(finding)
            file_ref = finding.get("file") or "unknown"
            line = finding.get("line")
            line_cell = line if line is not None else "—"
            lines.append(f"| {severity} | {issue} | `{file_ref}` | {line_cell} |")

    if findings:
        lines.extend(["", "# Findings", ""])
        for index, finding in enumerate(findings, start=1):
            lines.extend(_markdown_finding_short(index, finding))

    lines.extend(
        [
            "",
            "---",
            "",
            f"_AI Security Assistant · {report.get('project_name')} · "
            f"{report.get('scanned_at')} · Deterministic engine is source of truth._",
            "",
        ]
    )
    return "\n".join(lines)


def _markdown_finding_short(index: int, finding: dict[str, Any]) -> list[str]:
    severity = _severity_label(_finding_severity(finding))
    file_ref = finding.get("file") or "unknown"
    line = finding.get("line")
    loc = f"{file_ref}:{line}" if line is not None else file_ref
    card = [
        f"## {index}. {_finding_title(finding)}",
        "",
        f"`{severity}` · `{loc}`",
        "",
    ]

    flow = format_evidence_flow_text(build_evidence_flow(finding))
    if flow:
        card.extend(["**Evidence**", "", "```text", flow, "```", ""])

    why = _first_sentence(
        finding.get("missing_control")
        or "Potential security issue indicated by the deterministic analyzer."
    )
    impact = _first_sentence(
        finding.get("impact")
        or "Impact depends on whether untrusted callers can trigger this behavior."
    )
    remediation = "; ".join(_remediation_items(finding))
    card.extend(
        [
            f"**Why:** {why}",
            "",
            f"**Impact:** {impact}",
            "",
            f"**Remediation:** {remediation}",
            "",
        ]
    )

    explanation = _finding_ai_explanation(finding)
    if explanation:
        card.extend([f"**AI Explanation:** {_short_text(explanation, max_len=220)}", ""])

    suggestion = finding.get("ai_fix_suggestion")
    if isinstance(suggestion, dict) and suggestion.get("replacement_code"):
        card.extend(
            [
                "**AI Fix Suggestion**",
                "",
                _short_text(suggestion.get("summary") or "Suggested fix", max_len=120),
                "",
                "```python",
                str(suggestion.get("replacement_code")),
                "```",
                "",
            ]
        )

    return card


def render_html_report(report: dict[str, Any]) -> str:
    summary = report.get("summary") or {}
    findings = report.get("findings") or []
    project_name = report.get("project_name") or "project"

    overview_rows = "".join(
        (
            "<tr>"
            f"<td><span class='badge {escape_html(_finding_severity(finding))}'>"
            f"{escape_html(_severity_label(_finding_severity(finding)))}</span></td>"
            f"<td><a href='#finding-{index}'>{escape_html(_finding_title(finding))}</a></td>"
            f"<td><code>{escape_html(finding.get('file') or 'unknown')}</code></td>"
            f"<td>{escape_html(finding.get('line') if finding.get('line') is not None else '—')}</td>"
            "</tr>"
        )
        for index, finding in enumerate(findings, start=1)
    ) or (
        "<tr><td colspan='4' class='muted'>No findings detected.</td></tr>"
    )

    finding_cards = "".join(
        _html_finding_details(index, finding)
        for index, finding in enumerate(findings, start=1)
    )
    if not finding_cards:
        finding_cards = "<p class='muted'>No findings detected.</p>"

    ai_note = ""
    if report.get("ai_executive_summary"):
        ai_note = (
            "<p class='ai-note'><span class='muted'>AI summary:</span> "
            f"{escape_html(_short_text(report['ai_executive_summary'], max_len=220))}</p>"
        )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Security Report — {escape_html(project_name)}</title>
  <style>
    :root {{
      --bg: #0b1220;
      --card: #152033;
      --elevated: #111827;
      --text: #e5eef7;
      --muted: #93a4b8;
      --border: #243247;
      --high: #ef4444;
      --medium: #f59e0b;
      --low: #3b82f6;
      --accent: #2dd4bf;
      --code: #0a101a;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: "IBM Plex Sans", "Segoe UI", sans-serif;
      color: var(--text);
      background:
        radial-gradient(900px 420px at 8% -12%, rgba(45, 212, 191, 0.10), transparent 55%),
        var(--bg);
      line-height: 1.45;
    }}
    .wrap {{
      max-width: 980px;
      margin: 0 auto;
      padding: 1.5rem 1.15rem 2.25rem;
    }}
    .eyebrow {{
      color: var(--accent);
      font-size: 0.75rem;
      letter-spacing: 0.08em;
      text-transform: uppercase;
      margin: 0 0 0.25rem;
    }}
    h1 {{ margin: 0 0 0.2rem; font-size: 1.65rem; }}
    h2 {{ margin: 0 0 0.75rem; font-size: 1.05rem; }}
    .muted {{ color: var(--muted); }}
    .meta {{ color: var(--muted); margin: 0 0 1rem; font-size: 0.92rem; }}
    .cards {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
      gap: 0.65rem;
      margin-bottom: 1rem;
    }}
    .card {{
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 0.75rem 0.85rem;
    }}
    .card .label {{
      font-size: 0.7rem;
      color: var(--muted);
      text-transform: uppercase;
      letter-spacing: 0.04em;
    }}
    .card .value {{
      font-size: 1.25rem;
      font-weight: 700;
      margin-top: 0.2rem;
    }}
    .score {{ color: var(--accent); }}
    .panel {{
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 1rem 1.05rem;
      margin-top: 0.9rem;
    }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{
      text-align: left;
      padding: 0.55rem 0.35rem;
      border-bottom: 1px solid var(--border);
      vertical-align: top;
      font-size: 0.92rem;
    }}
    th {{
      font-size: 0.72rem;
      color: var(--muted);
      text-transform: uppercase;
      letter-spacing: 0.04em;
    }}
    td:last-child, th:last-child {{ text-align: right; white-space: nowrap; }}
    a {{ color: var(--accent); text-decoration: none; }}
    a:hover {{ text-decoration: underline; }}
    .badge {{
      display: inline-block;
      padding: 0.1rem 0.45rem;
      border-radius: 999px;
      font-size: 0.72rem;
      font-weight: 700;
      color: #fff;
      background: #64748b;
    }}
    .badge.high {{ background: var(--high); }}
    .badge.medium {{ background: var(--medium); }}
    .badge.low {{ background: var(--low); }}
    details.finding {{
      background: var(--elevated);
      border: 1px solid var(--border);
      border-radius: 10px;
      margin-top: 0.65rem;
      overflow: hidden;
    }}
    details.finding > summary {{
      list-style: none;
      cursor: pointer;
      display: grid;
      grid-template-columns: auto 1fr auto auto;
      gap: 0.65rem;
      align-items: center;
      padding: 0.7rem 0.85rem;
    }}
    details.finding > summary::-webkit-details-marker {{ display: none; }}
    details.finding > summary:hover {{ background: rgba(255,255,255,0.03); }}
    details.finding[open] > summary {{
      border-bottom: 1px solid var(--border);
    }}
    .summary-issue {{ font-weight: 600; }}
    .summary-file, .summary-line {{
      color: var(--muted);
      font-family: "IBM Plex Mono", ui-monospace, monospace;
      font-size: 0.82rem;
    }}
    .summary-line {{ text-align: right; }}
    .detail {{
      padding: 0.85rem 0.95rem 1rem;
      display: grid;
      gap: 0.75rem;
    }}
    .detail h3 {{
      margin: 0 0 0.3rem;
      font-size: 0.72rem;
      color: var(--muted);
      text-transform: uppercase;
      letter-spacing: 0.04em;
      font-weight: 600;
    }}
    .detail p {{ margin: 0; font-size: 0.92rem; }}
    .detail ul {{ margin: 0; padding-left: 1.1rem; }}
    .detail li {{ margin: 0.15rem 0; font-size: 0.92rem; }}
    pre, .flow {{
      margin: 0;
      background: var(--code);
      color: #dbeafe;
      padding: 0.7rem 0.8rem;
      border-radius: 8px;
      overflow-x: auto;
      white-space: pre-wrap;
      word-break: break-word;
      font-size: 0.84rem;
      border: 1px solid var(--border);
      font-family: "IBM Plex Mono", ui-monospace, monospace;
    }}
    .ai-fix, .ai-explain {{
      padding: 0.7rem 0.8rem;
      border-radius: 8px;
      border: 1px dashed rgba(45, 212, 191, 0.4);
      background: rgba(45, 212, 191, 0.06);
    }}
    .ai-explain {{
      border-color: rgba(59, 130, 246, 0.4);
      background: rgba(59, 130, 246, 0.07);
    }}
    .ai-note {{
      margin: 0.75rem 0 0;
      font-size: 0.9rem;
    }}
    .disclaimer {{
      margin: 0 0 0.35rem !important;
      font-style: italic;
      color: var(--muted);
      font-size: 0.8rem !important;
    }}
    footer {{
      margin-top: 1rem;
      color: var(--muted);
      font-size: 0.82rem;
    }}
    code {{ font-family: "IBM Plex Mono", ui-monospace, monospace; font-size: 0.86em; }}
    @media (max-width: 720px) {{
      details.finding > summary {{
        grid-template-columns: auto 1fr;
        grid-template-areas:
          "badge issue"
          "file line";
      }}
      .summary-issue {{ grid-area: issue; }}
      .badge {{ grid-area: badge; }}
      .summary-file {{ grid-area: file; }}
      .summary-line {{ grid-area: line; }}
    }}
  </style>
</head>
<body>
  <div class="wrap">
    <p class="eyebrow">AI Security Assistant</p>
    <h1>{escape_html(project_name)}</h1>
    <p class="meta">{escape_html(report.get('scanned_at'))} · <code>{escape_html(report.get('project_path'))}</code></p>

    <section id="summary" aria-label="Scan summary">
      <div class="cards">
        <div class="card"><div class="label">Security Score</div><div class="value score">{escape_html(report.get('security_score'))}/100</div></div>
        <div class="card"><div class="label">Files Scanned</div><div class="value">{escape_html(report.get('files_scanned'))}</div></div>
        <div class="card"><div class="label">Total Findings</div><div class="value">{escape_html(summary.get('total_findings'))}</div></div>
        <div class="card"><div class="label">High</div><div class="value">{escape_html(summary.get('high'))}</div></div>
        <div class="card"><div class="label">Medium</div><div class="value">{escape_html(summary.get('medium'))}</div></div>
        <div class="card"><div class="label">Low</div><div class="value">{escape_html(summary.get('low'))}</div></div>
      </div>
      {ai_note}
    </section>

    <section id="overview" class="panel">
      <h2>Findings Overview</h2>
      <table>
        <thead>
          <tr><th>Severity</th><th>Issue</th><th>File</th><th>Line</th></tr>
        </thead>
        <tbody>
          {overview_rows}
        </tbody>
      </table>
    </section>

    <section id="findings" class="panel">
      <h2>Finding Details</h2>
      {finding_cards}
    </section>

    <footer>
      Generated by AI Security Assistant for <strong>{escape_html(project_name)}</strong>.
      Deterministic engine is the source of truth.
    </footer>
  </div>
</body>
</html>
"""


def _html_finding_details(index: int, finding: dict[str, Any]) -> str:
    severity = _finding_severity(finding)
    file_ref = finding.get("file") or "unknown"
    line = finding.get("line")
    line_display = line if line is not None else "—"
    flow = format_evidence_flow_text(build_evidence_flow(finding))
    evidence_html = (
        f"<pre class='flow'>{escape_html(flow)}</pre>"
        if flow
        else "<p class='muted'>No evidence locations provided.</p>"
    )
    rec_html = (
        "<ul>"
        + "".join(f"<li>{escape_html(item)}</li>" for item in _remediation_items(finding))
        + "</ul>"
    )

    suggestion = finding.get("ai_fix_suggestion")
    suggestion_html = ""
    if isinstance(suggestion, dict) and suggestion.get("replacement_code"):
        suggestion_html = f"""
        <div class="ai-fix">
          <h3>AI Fix Suggestion</h3>
          <p class="disclaimer">AI-generated. Review before applying.</p>
          <p>{escape_html(suggestion.get('summary'))}</p>
          <pre>{escape_html(suggestion.get('replacement_code'))}</pre>
        </div>
        """

    explanation = _finding_ai_explanation(finding)
    explanation_html = ""
    if explanation:
        explanation_html = f"""
        <div class="ai-explain">
          <h3>AI Explanation</h3>
          <p class="disclaimer">AI-generated. Does not classify the finding.</p>
          <p>{escape_html(explanation)}</p>
        </div>
        """

    return f"""
    <details class="finding" id="finding-{index}">
      <summary>
        <span class="badge {escape_html(severity)}">{escape_html(_severity_label(severity))}</span>
        <span class="summary-issue">{escape_html(_finding_title(finding))}</span>
        <span class="summary-file">{escape_html(file_ref)}</span>
        <span class="summary-line">{escape_html(line_display)}</span>
      </summary>
      <div class="detail">
        <div>
          <h3>Evidence</h3>
          {evidence_html}
        </div>
        <div>
          <h3>Why</h3>
          <p>{escape_html(finding.get('missing_control') or 'Potential security issue indicated by the deterministic analyzer.')}</p>
        </div>
        <div>
          <h3>Impact</h3>
          <p>{escape_html(finding.get('impact') or 'Impact depends on whether untrusted callers can trigger this behavior.')}</p>
        </div>
        <div>
          <h3>Remediation</h3>
          {rec_html}
        </div>
        {explanation_html}
        {suggestion_html}
      </div>
    </details>
    """
