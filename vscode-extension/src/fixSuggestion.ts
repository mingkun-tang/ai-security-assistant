/** Parse CLI suggest-fix --json payloads (no OpenAI calls). */

import type { FixSuggestion, FixSuggestionPayload } from "./types";

function asRecord(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

function asString(value: unknown, fallback = ""): string {
  return typeof value === "string" ? value : fallback;
}

function asArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

export const FIX_SAFETY_LABEL =
  "AI-generated suggestion. Review before applying.";

export function parseFixSuggestionPayload(payload: unknown): FixSuggestionPayload {
  const root = asRecord(payload);
  if (!root) {
    return {
      available: false,
      message: "AI fix suggestion unavailable.",
      suggestion: null,
    };
  }

  const available = root.available === true;
  const rawSuggestion = asRecord(root.suggestion);
  let suggestion: FixSuggestion | null = null;

  if (available && rawSuggestion) {
    const replacementCode = asString(rawSuggestion.replacement_code).trim();
    const explanation = asString(rawSuggestion.explanation).trim();
    const summary = asString(rawSuggestion.summary).trim();
    const issueType = asString(rawSuggestion.issue_type).trim();
    if (replacementCode && explanation && summary && issueType) {
      suggestion = {
        summary,
        replacementCode,
        explanation,
        warnings: asArray(rawSuggestion.warnings)
          .map((item) => asString(item).trim())
          .filter(Boolean),
        disclaimer:
          asString(rawSuggestion.disclaimer).trim() || FIX_SAFETY_LABEL,
        issueType,
      };
    }
  }

  const finding = asRecord(root.finding);
  return {
    available: Boolean(suggestion),
    message: suggestion
      ? null
      : asString(root.message, "AI fix suggestion unavailable.") ||
        "AI fix suggestion unavailable.",
    suggestion,
    sourceSnippet: asString(root.source_snippet) || undefined,
    finding: finding
      ? {
          issueType: asString(finding.issue_type),
          displayName: asString(finding.display_name) || undefined,
          confidence: asString(finding.confidence) || undefined,
        }
      : null,
  };
}

export function formatFixSuggestionSection(suggestion: FixSuggestion): string {
  const lines = [
    "AI Fix Suggestion",
    "-----------------",
    "",
    FIX_SAFETY_LABEL,
    "",
    suggestion.summary,
    "",
    "Suggested replacement:",
    "",
    suggestion.replacementCode,
    "",
    "Why:",
    suggestion.explanation,
  ];
  if (suggestion.warnings.length) {
    lines.push("", "Warnings:");
    for (const warning of suggestion.warnings) {
      lines.push(`- ${warning}`);
    }
  }
  return lines.join("\n");
}
