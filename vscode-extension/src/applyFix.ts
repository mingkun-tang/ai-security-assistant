/** Pure helpers for applying AI fix suggestions. No detection logic. */

export interface TextRange {
  /** 0-based start offset in the full document text. */
  startOffset: number;
  /** 0-based end offset (exclusive). */
  endOffset: number;
  /** 0-based start line. */
  startLine: number;
  /** 0-based end line. */
  endLine: number;
  matchedText: string;
}

export interface ApplyFixInput {
  documentText: string;
  expectedSnippet: string;
  replacementCode: string;
  preferredLine?: number | null; // 1-based from analyzer
}

export type ApplyFixPlanResult =
  | { ok: true; range: TextRange; replacement: string }
  | {
      ok: false;
      reason:
        | "missing_suggestion"
        | "missing_snippet"
        | "snippet_not_found"
        | "stale_source"
        | "empty_replacement";
      message: string;
    };

export const STALE_SOURCE_MESSAGE =
  "Source changed since this suggestion was generated. Regenerate the fix before applying.";

export const APPLY_CONFIRM_TITLE = "Apply this AI-generated security fix?";
export const APPLY_SAFETY_LABEL =
  "AI-generated suggestion — review before applying.";

/** Diff preview uses untitled buffers and must never be treated as the write path. */
export const DIFF_PREVIEW_ONLY_LABEL =
  "Preview only — does not modify your file. Use Apply Suggested Fix to write the change.";

export const FIX_APPLIED_CLEARED_MESSAGE =
  "Fix applied and finding no longer detected.";

export const FIX_APPLIED_STILL_PRESENT_MESSAGE =
  "Fix applied, but the finding is still detected. Review the result.";

export const FIX_APPLIED_RESCAN_FAILED_MESSAGE =
  "Fix applied, but rescan failed. Review the file and scan again.";

/**
 * Apply writes through WorkspaceEdit on the real document URI.
 * Opening a vscode.diff preview is optional and never required to apply.
 */
export function applyRequiresDiffPreview(): boolean {
  return false;
}

export function rescanOutcomeMessage(findingStillDetected: boolean): string {
  return findingStillDetected
    ? FIX_APPLIED_STILL_PRESENT_MESSAGE
    : FIX_APPLIED_CLEARED_MESSAGE;
}

function normalizeNewlines(text: string): string {
  return text.replace(/\r\n/g, "\n").replace(/\r/g, "\n");
}

function detectNewline(text: string): "\r\n" | "\n" {
  return text.includes("\r\n") ? "\r\n" : "\n";
}

function leadingWhitespace(line: string): string {
  const match = /^[ \t]*/.exec(line);
  return match ? match[0] : "";
}

function lineOfOffset(text: string, offset: number): number {
  return normalizeNewlines(text.slice(0, offset)).split("\n").length - 1;
}

/**
 * Indent replacement lines to match the first line of the matched snippet,
 * preserving relative indentation inside the replacement.
 */
export function alignReplacementIndent(
  matchedText: string,
  replacementCode: string,
  newline: "\r\n" | "\n" = "\n",
): string {
  const matchedLines = normalizeNewlines(matchedText).split("\n");
  const baseIndent = leadingWhitespace(matchedLines[0] || "");
  const replacementLines = normalizeNewlines(replacementCode.trimEnd()).split(
    "\n",
  );

  let minIndent = Number.POSITIVE_INFINITY;
  for (const line of replacementLines) {
    if (!line.trim()) {
      continue;
    }
    minIndent = Math.min(minIndent, leadingWhitespace(line).length);
  }
  if (!Number.isFinite(minIndent)) {
    minIndent = 0;
  }

  const aligned = replacementLines.map((line) => {
    if (!line.trim()) {
      return "";
    }
    return baseIndent + line.slice(minIndent);
  });

  return aligned.join(newline);
}

function snippetVariants(expectedSnippet: string): string[] {
  const normalized = normalizeNewlines(expectedSnippet).trimEnd();
  if (!normalized) {
    return [];
  }
  return [normalized, normalized.replace(/\n/g, "\r\n")];
}

export function findSnippetRange(
  documentText: string,
  expectedSnippet: string,
  preferredLine?: number | null,
): TextRange | null {
  const variants = snippetVariants(expectedSnippet);
  if (!variants.length) {
    return null;
  }

  type Candidate = { start: number; matchedText: string };
  const candidates: Candidate[] = [];

  for (const variant of variants) {
    let from = 0;
    while (from <= documentText.length) {
      const index = documentText.indexOf(variant, from);
      if (index < 0) {
        break;
      }
      candidates.push({
        start: index,
        matchedText: documentText.slice(index, index + variant.length),
      });
      from = index + 1;
    }
  }

  // Deduplicate by start offset.
  const unique = new Map<number, Candidate>();
  for (const candidate of candidates) {
    unique.set(candidate.start, candidate);
  }
  const list = [...unique.values()];
  if (!list.length) {
    return null;
  }

  let chosen = list[0];
  if (preferredLine != null && preferredLine > 0) {
    const preferredIndex = preferredLine - 1;
    let bestDistance = Number.POSITIVE_INFINITY;
    for (const candidate of list) {
      const line = lineOfOffset(documentText, candidate.start);
      const distance = Math.abs(line - preferredIndex);
      if (distance < bestDistance) {
        bestDistance = distance;
        chosen = candidate;
      }
    }
  }

  // Expand to include leading indentation on the first matched line.
  let start = chosen.start;
  while (start > 0) {
    const previous = documentText[start - 1];
    if (previous === " " || previous === "\t") {
      start -= 1;
      continue;
    }
    break;
  }

  const matchedText = documentText.slice(
    start,
    chosen.start + chosen.matchedText.length,
  );
  const startLine = lineOfOffset(documentText, start);
  const endLine =
    startLine + normalizeNewlines(matchedText).split("\n").length - 1;

  return {
    startOffset: start,
    endOffset: start + matchedText.length,
    startLine,
    endLine,
    matchedText,
  };
}

export function verifySnippetStillMatches(
  documentText: string,
  expectedSnippet: string,
  range: TextRange,
): boolean {
  const current = documentText.slice(range.startOffset, range.endOffset);
  const currentNorm = normalizeNewlines(current).trimEnd();
  const expectedNorm = normalizeNewlines(expectedSnippet).trimEnd();
  // Allow leading indentation that was expanded onto the matched range.
  return (
    currentNorm === expectedNorm ||
    currentNorm.trimStart() === expectedNorm.trimStart()
  );
}

export function buildApplyFixPlan(input: ApplyFixInput): ApplyFixPlanResult {
  const expectedSnippet = (input.expectedSnippet || "").trimEnd();
  const replacementCode = (input.replacementCode || "").trimEnd();

  if (!replacementCode) {
    return {
      ok: false,
      reason: "empty_replacement",
      message: "Fix suggestion is missing replacement code.",
    };
  }
  if (!expectedSnippet) {
    return {
      ok: false,
      reason: "missing_snippet",
      message: "Fix suggestion is missing the original source snippet.",
    };
  }

  const range = findSnippetRange(
    input.documentText,
    expectedSnippet,
    input.preferredLine,
  );
  if (!range) {
    return {
      ok: false,
      reason: "snippet_not_found",
      message: STALE_SOURCE_MESSAGE,
    };
  }

  if (!verifySnippetStillMatches(input.documentText, expectedSnippet, range)) {
    return {
      ok: false,
      reason: "stale_source",
      message: STALE_SOURCE_MESSAGE,
    };
  }

  const newline = detectNewline(input.documentText);
  const replacement = alignReplacementIndent(
    range.matchedText,
    replacementCode,
    newline,
  );

  return { ok: true, range, replacement };
}

export function findingStillPresent(
  findings: Array<{ issueType: string; line?: number | null }>,
  issueType: string,
  line?: number | null,
): boolean {
  const matches = findings.filter((finding) => finding.issueType === issueType);
  if (!matches.length) {
    return false;
  }
  if (line == null) {
    return true;
  }
  return matches.some(
    (finding) => finding.line == null || finding.line === line,
  );
}

export type ApplyDecision = "apply" | "cancel";

export function resolveApplyDecision(choice: string | undefined): ApplyDecision {
  return choice === "Apply Fix" ? "apply" : "cancel";
}
