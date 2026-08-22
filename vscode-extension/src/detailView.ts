/** Build and render finding detail models (deterministic + optional AI). */

import type { FindingDetailModel, FixSuggestion, SecurityFinding } from "./types";
import { formatEvidenceFlow } from "./evidenceFlow";
import { formatFixSuggestionSection } from "./fixSuggestion";
import { APPLY_SAFETY_LABEL } from "./applyFix";

export const AI_EXPLANATION_DISCLAIMER =
  "AI explains this finding but does not determine or classify it. The deterministic engine remains the source of truth.";

export function titleConfidence(confidence: string): string {
  const text = String(confidence || "low");
  return text.charAt(0).toUpperCase() + text.slice(1);
}

export interface DetailViewState {
  fixSuggestion?: FixSuggestion;
  fixStatus?: FindingDetailModel["fixStatus"];
  fixMessage?: string;
  sourceSnippet?: string;
}

export function buildFindingDetailModel(
  finding: SecurityFinding,
  state: DetailViewState = {},
): FindingDetailModel {
  const recommendations = finding.recommendations.filter(Boolean);
  const primary =
    finding.remediation ||
    recommendations[0] ||
    undefined;
  const additional = recommendations.filter((item) => item !== primary);

  const aiExplanation = finding.aiExplanation?.trim() || undefined;
  const sourceSnippet =
    state.sourceSnippet?.trim() ||
    finding.snippet?.trim() ||
    finding.evidenceSteps.find((step) => step.kind !== "input_source")?.snippet ||
    finding.evidenceSteps[0]?.snippet;

  return {
    issue: finding.displayName,
    confidence: String(finding.confidence || "low"),
    confidenceLabel: titleConfidence(finding.confidence),
    file: finding.file,
    line: finding.line,
    evidenceSteps: finding.evidenceSteps,
    whyFlagged: finding.explanation,
    impact:
      finding.impact?.trim() ||
      "Impact depends on whether untrusted callers can trigger this behavior.",
    primaryRemediation: primary,
    additionalRemediations: additional,
    aiExplanation,
    showAiSection: Boolean(aiExplanation),
    aiDisclaimer: AI_EXPLANATION_DISCLAIMER,
    sourceSnippet,
    fixSuggestion: state.fixSuggestion,
    fixStatus: state.fixStatus || "idle",
    fixMessage: state.fixMessage,
    fixSafetyLabel: APPLY_SAFETY_LABEL,
  };
}

export function formatRemediationSection(model: FindingDetailModel): string {
  const lines: string[] = ["Recommended Fix", "---------------"];
  if (model.primaryRemediation) {
    lines.push(model.primaryRemediation);
  } else {
    lines.push("Review the flagged code and apply the safest available control.");
  }
  if (model.additionalRemediations.length) {
    lines.push("");
    lines.push("Additional guidance:");
    for (const item of model.additionalRemediations) {
      lines.push(`- ${item}`);
    }
  }
  return lines.join("\n");
}

export function formatFindingDetailMarkdown(model: FindingDetailModel): string {
  const lines: string[] = [
    `# ${model.issue}`,
    "",
    `**Confidence:** ${model.confidenceLabel}`,
    "",
    `**File:** \`${model.file}\`${model.line != null ? `:${model.line}` : ""}`,
    "",
    "## Evidence",
    "",
  ];

  const flow = formatEvidenceFlow(model.evidenceSteps);
  if (flow) {
    lines.push("```");
    lines.push(flow);
    lines.push("```");
  } else {
    lines.push("_No structured evidence locations were provided by the analyzer._");
  }

  lines.push("", "## Why this was flagged", "", model.whyFlagged);
  lines.push("", "## Impact", "", model.impact);
  lines.push("", "## Recommended Fix", "");
  if (model.primaryRemediation) {
    lines.push(model.primaryRemediation);
  } else {
    lines.push("Review the flagged code and apply the safest available control.");
  }
  if (model.additionalRemediations.length) {
    lines.push("", "Additional guidance:");
    for (const item of model.additionalRemediations) {
      lines.push(`- ${item}`);
    }
  }

  if (model.showAiSection && model.aiExplanation) {
    lines.push("", "## AI Explanation", "");
    lines.push(`_${model.aiDisclaimer}_`);
    lines.push("");
    lines.push(model.aiExplanation);
  }

  if (model.fixSuggestion) {
    lines.push("", formatFixSuggestionSection(model.fixSuggestion));
    if (model.sourceSnippet) {
      lines.push("", "Current Code", "------------", "", model.sourceSnippet);
      lines.push(
        "",
        "Suggested Code",
        "--------------",
        "",
        model.fixSuggestion.replacementCode,
      );
    }
  } else if (model.fixStatus === "unavailable") {
    lines.push("", "## AI Fix Suggestion", "", model.fixMessage || "AI fix suggestion unavailable.");
  }

  lines.push(
    "",
    "---",
    "",
    "_Deterministic engine finding. AI never overrides this result._",
  );

  return lines.join("\n");
}

export function renderFindingDetailHtml(model: FindingDetailModel): string {
  const flow = formatEvidenceFlow(model.evidenceSteps);
  const escape = (value: string): string =>
    value
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");

  const additional = model.additionalRemediations
    .map((item) => `<li>${escape(item)}</li>`)
    .join("");

  const aiBlock =
    model.showAiSection && model.aiExplanation
      ? `
      <section class="ai">
        <h2>AI Explanation</h2>
        <p class="disclaimer">${escape(model.aiDisclaimer)}</p>
        <p>${escape(model.aiExplanation)}</p>
      </section>`
      : "";

  let fixBlock = `
    <section class="fix-suggest">
      <h2>AI Fix Suggestion</h2>
      <p class="disclaimer">${escape(model.fixSafetyLabel)}</p>
      <button id="generate-fix" ${model.fixStatus === "loading" ? "disabled" : ""}>
        ${model.fixStatus === "loading" ? "Generating…" : "Generate AI Fix Suggestion"}
      </button>
  `;

  if (model.fixStatus === "loading") {
    fixBlock += `<p class="status">Generating fix suggestion…</p>`;
  } else if (model.fixStatus === "unavailable") {
    fixBlock += `<p class="status">${escape(model.fixMessage || "AI fix suggestion unavailable.")}</p>`;
  } else if (model.fixSuggestion) {
    const suggestion = model.fixSuggestion;
    fixBlock += `
      <p><strong>${escape(suggestion.summary)}</strong></p>
      <h3>Suggested replacement</h3>
      <pre class="flow">${escape(suggestion.replacementCode)}</pre>
      <h3>Why</h3>
      <p>${escape(suggestion.explanation)}</p>
      ${
        suggestion.warnings.length
          ? `<h3>Warnings</h3><ul>${suggestion.warnings
              .map((item) => `<li>${escape(item)}</li>`)
              .join("")}</ul>`
          : ""
      }
      <h3>Current Code vs Suggested Code</h3>
      <div class="diff">
        <div>
          <h4>Current Code</h4>
          <pre class="flow">${escape(model.sourceSnippet || "(snippet unavailable)")}</pre>
        </div>
        <div>
          <h4>Suggested Code</h4>
          <pre class="flow">${escape(suggestion.replacementCode)}</pre>
        </div>
      </div>
      <button id="show-diff">Open Diff Preview</button>
      <button id="apply-fix">Apply Suggested Fix</button>
      <p class="disclaimer">${escape(model.fixSafetyLabel)}</p>
      <p class="disclaimer">This extension only edits the exact suggested range after you confirm. It does not claim the result is secure.</p>
    `;
  }

  fixBlock += `</section>`;

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline';" />
  <style>
    :root { color-scheme: light dark; }
    body {
      font-family: var(--vscode-font-family);
      font-size: var(--vscode-font-size);
      color: var(--vscode-foreground);
      background: var(--vscode-editor-background);
      line-height: 1.5;
      padding: 1.25rem 1.5rem 2rem;
      max-width: 860px;
    }
    h1 { font-size: 1.5rem; margin: 0 0 0.35rem; }
    h2 {
      font-size: 1.05rem;
      margin: 1.4rem 0 0.55rem;
      border-bottom: 1px solid var(--vscode-panel-border, rgba(127,127,127,0.35));
      padding-bottom: 0.25rem;
    }
    h3 { font-size: 0.95rem; margin: 1rem 0 0.35rem; }
    h4 { margin: 0 0 0.35rem; font-size: 0.9rem; }
    .meta { opacity: 0.9; margin-bottom: 0.75rem; }
    .badge {
      display: inline-block;
      padding: 0.1rem 0.45rem;
      border-radius: 999px;
      font-size: 0.85rem;
      background: var(--vscode-badge-background);
      color: var(--vscode-badge-foreground);
    }
    pre.flow {
      background: var(--vscode-textCodeBlock-background, rgba(127,127,127,0.12));
      border: 1px solid var(--vscode-panel-border, rgba(127,127,127,0.25));
      border-radius: 6px;
      padding: 0.85rem 1rem;
      overflow-x: auto;
      white-space: pre;
      font-family: var(--vscode-editor-font-family, monospace);
    }
    .fix {
      border-left: 3px solid var(--vscode-focusBorder, #3794ff);
      padding: 0.35rem 0 0.35rem 0.85rem;
      margin: 0.5rem 0 0.75rem;
      font-weight: 600;
    }
    .ai, .fix-suggest {
      margin-top: 1.25rem;
      padding: 0.85rem 1rem;
      border-radius: 6px;
      border: 1px dashed var(--vscode-panel-border, rgba(127,127,127,0.45));
      background: var(--vscode-textBlockQuote-background, rgba(127,127,127,0.08));
    }
    .disclaimer { font-style: italic; opacity: 0.85; margin-top: 0.35rem; }
    .status { margin-top: 0.75rem; }
    .diff {
      display: grid;
      grid-template-columns: 1fr;
      gap: 0.75rem;
    }
    @media (min-width: 720px) {
      .diff { grid-template-columns: 1fr 1fr; }
    }
    button {
      margin-top: 0.5rem;
      margin-right: 0.5rem;
      padding: 0.4rem 0.75rem;
      border: 1px solid var(--vscode-button-border, transparent);
      border-radius: 4px;
      background: var(--vscode-button-background);
      color: var(--vscode-button-foreground);
      cursor: pointer;
    }
    button:disabled { opacity: 0.6; cursor: default; }
    footer { margin-top: 1.5rem; opacity: 0.7; font-size: 0.9rem; }
    code { font-family: var(--vscode-editor-font-family, monospace); }
  </style>
</head>
<body>
  <h1>${escape(model.issue)}</h1>
  <div class="meta">
    <span class="badge">${escape(model.confidenceLabel)}</span>
    &nbsp;·&nbsp;
    <code>${escape(model.file)}${model.line != null ? `:${model.line}` : ""}</code>
  </div>

  <h2>Evidence</h2>
  ${
    flow
      ? `<pre class="flow">${escape(flow)}</pre>`
      : "<p><em>No structured evidence locations were provided by the analyzer.</em></p>"
  }

  <h2>Why this was flagged</h2>
  <p>${escape(model.whyFlagged)}</p>

  <h2>Impact</h2>
  <p>${escape(model.impact)}</p>

  <h2>Recommended Fix</h2>
  <div class="fix">${escape(
    model.primaryRemediation ||
      "Review the flagged code and apply the safest available control.",
  )}</div>
  ${additional ? `<p>Additional guidance:</p><ul>${additional}</ul>` : ""}

  ${aiBlock}
  ${fixBlock}

  <footer>Deterministic engine finding. AI never overrides this result.</footer>
  <script>
    const vscode = acquireVsCodeApi();
    const generate = document.getElementById('generate-fix');
    if (generate) {
      generate.addEventListener('click', () => {
        vscode.postMessage({ command: 'generateFix' });
      });
    }
    const showDiff = document.getElementById('show-diff');
    if (showDiff) {
      showDiff.addEventListener('click', () => {
        vscode.postMessage({ command: 'showDiff' });
      });
    }
    const applyFix = document.getElementById('apply-fix');
    if (applyFix) {
      applyFix.addEventListener('click', () => {
        vscode.postMessage({ command: 'applyFix' });
      });
    }
  </script>
</body>
</html>`;
}
