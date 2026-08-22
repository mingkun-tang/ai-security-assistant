/** Normalize CLI JSON into SecurityFinding records. Detection stays in the Python engine. */

import type { Confidence, ScanResult, SecurityFinding } from "./types";

function asRecord(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

function asArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function asString(value: unknown, fallback = ""): string {
  return typeof value === "string" ? value : fallback;
}

function asNumber(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function titleConfidence(confidence: Confidence): string {
  const text = String(confidence || "low");
  return text.charAt(0).toUpperCase() + text.slice(1);
}

function firstRecommendation(value: unknown): string | undefined {
  const items = asArray(value)
    .map((item) => asString(item).trim())
    .filter(Boolean);
  return items[0];
}

function locationFromEvidence(finding: Record<string, unknown>): {
  file?: string;
  line: number | null;
  column: number | null;
  snippet?: string;
} {
  for (const item of asArray(finding.evidence_locations)) {
    const record = asRecord(item);
    const location = asRecord(record?.location);
    if (!location) {
      continue;
    }
    return {
      file: asString(location.path) || undefined,
      line: asNumber(location.line),
      column: asNumber(location.column),
      snippet: asString(location.snippet) || undefined,
    };
  }
  return { line: null, column: null };
}

function buildFinding(
  raw: Record<string, unknown>,
  index: number,
  fallbackFile?: string,
): SecurityFinding {
  const evidence = locationFromEvidence(raw);
  const file =
    asString(raw.file) ||
    evidence.file ||
    fallbackFile ||
    "";
  const displayName = asString(raw.display_name, "Security Finding");
  const confidence = asString(raw.confidence, "low") as Confidence;
  const explanation =
    asString(raw.missing_control).trim() ||
    asString(raw.impact).trim() ||
    "Potential security issue indicated by the deterministic analyzer.";
  const remediation = firstRecommendation(raw.recommendations);
  const aiExplanation =
    asString(raw.ai_explanation).trim() ||
    asString(asRecord(raw.ai)?.explanation).trim() ||
    undefined;

  return {
    id: `${file}:${asNumber(raw.line) ?? evidence.line ?? 0}:${asString(raw.issue_type, "finding")}:${index}`,
    issueType: asString(raw.issue_type, "unknown"),
    displayName,
    confidence,
    file,
    line: asNumber(raw.line) ?? evidence.line,
    column: asNumber(raw.column) ?? evidence.column,
    snippet: asString(raw.snippet) || evidence.snippet,
    explanation,
    remediation,
    aiExplanation: aiExplanation || undefined,
  };
}

/** Parse analyze-file --json output. */
export function parseAnalyzeFileJson(payload: unknown): ScanResult {
  const root = asRecord(payload);
  if (!root) {
    throw new Error("Analyzer returned invalid JSON (expected an object).");
  }

  const source = asRecord(root.source);
  const fallbackFile = asString(source?.path);
  const findings = asArray(root.findings).map((item, index) => {
    const record = asRecord(item);
    if (!record) {
      throw new Error(`Analyzer finding at index ${index} is not an object.`);
    }
    return buildFinding(record, index, fallbackFile);
  });

  return { findings, project: fallbackFile };
}

/** Parse scan --json output. */
export function parseScanJson(payload: unknown): ScanResult {
  const root = asRecord(payload);
  if (!root) {
    throw new Error("Analyzer returned invalid JSON (expected an object).");
  }

  const findings = asArray(root.findings).map((item, index) => {
    const record = asRecord(item);
    if (!record) {
      throw new Error(`Analyzer finding at index ${index} is not an object.`);
    }
    return buildFinding(record, index);
  });

  return {
    findings,
    filesAnalyzed: asNumber(root.files_analyzed) ?? undefined,
    project: asString(root.project) || undefined,
  };
}

export function parseJsonText(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    throw new Error(`Analyzer returned invalid JSON: ${detail}`);
  }
}

export function formatFindingLabel(finding: SecurityFinding): string {
  return `${finding.displayName} — ${titleConfidence(finding.confidence)}`;
}

export function formatDiagnosticMessage(finding: SecurityFinding): string {
  const lines = [
    formatFindingLabel(finding),
    finding.explanation,
  ];
  if (finding.remediation) {
    lines.push(finding.remediation);
  }
  if (finding.aiExplanation) {
    lines.push(`AI: ${finding.aiExplanation}`);
  }
  return lines.join("\n");
}

export function groupFindingsByFile(
  findings: SecurityFinding[],
): Map<string, SecurityFinding[]> {
  const groups = new Map<string, SecurityFinding[]>();
  for (const finding of findings) {
    const key = finding.file || "unknown";
    const bucket = groups.get(key);
    if (bucket) {
      bucket.push(finding);
    } else {
      groups.set(key, [finding]);
    }
  }
  return groups;
}

export function confidenceToSeverityRank(confidence: Confidence): number {
  switch (String(confidence).toLowerCase()) {
    case "high":
      return 3;
    case "medium":
      return 2;
    default:
      return 1;
  }
}
