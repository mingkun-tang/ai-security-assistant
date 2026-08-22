/** Normalize CLI JSON into SecurityFinding records. Detection stays in the Python engine. */

import { buildEvidenceSteps } from "./evidenceFlow";
import { titleConfidence } from "./detailView";
import type {
  Confidence,
  EvidenceLocation,
  ScanResult,
  SecurityFinding,
} from "./types";

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

function recommendationsFrom(value: unknown): string[] {
  return asArray(value)
    .map((item) => asString(item).trim())
    .filter(Boolean);
}

function parseEvidenceLocation(value: unknown): EvidenceLocation | undefined {
  const record = asRecord(value);
  if (!record) {
    return undefined;
  }
  const location = asRecord(record.location);
  return {
    id: asString(record.id) || undefined,
    kind: asString(record.kind, "observation"),
    attrs: asRecord(record.attrs) || {},
    notes: asArray(record.notes).map((item) => asString(item)),
    location: location
      ? {
          path: asString(location.path) || undefined,
          line: asNumber(location.line),
          column: asNumber(location.column),
          snippet: asString(location.snippet) || undefined,
        }
      : undefined,
  };
}

function locationFromEvidence(facts: EvidenceLocation[]): {
  file?: string;
  line: number | null;
  column: number | null;
  snippet?: string;
} {
  for (const fact of facts) {
    const location = fact.location;
    if (!location?.path && location?.line == null && !location?.snippet) {
      continue;
    }
    // Prefer sink-like facts for primary caret position.
    if (fact.kind === "input_source") {
      continue;
    }
    return {
      file: location.path,
      line: location.line ?? null,
      column: location.column ?? null,
      snippet: location.snippet,
    };
  }
  for (const fact of facts) {
    if (fact.location) {
      return {
        file: fact.location.path,
        line: fact.location.line ?? null,
        column: fact.location.column ?? null,
        snippet: fact.location.snippet,
      };
    }
  }
  return { line: null, column: null };
}

function buildFinding(
  raw: Record<string, unknown>,
  index: number,
  fallbackFile?: string,
  rootFacts: EvidenceLocation[] = [],
): SecurityFinding {
  const evidenceLocations = asArray(raw.evidence_locations)
    .map(parseEvidenceLocation)
    .filter((item): item is EvidenceLocation => item !== undefined);

  // Prefer per-finding evidence; fall back to root facts for older payloads.
  const factsForFlow =
    evidenceLocations.length > 0 ? evidenceLocations : rootFacts;

  const evidence = locationFromEvidence(factsForFlow);
  const recommendations = recommendationsFrom(raw.recommendations);
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
  const remediation = recommendations[0];
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
    impact: asString(raw.impact).trim() || undefined,
    brokenTrust: asString(raw.broken_trust).trim() || undefined,
    remediation,
    recommendations,
    evidenceLocations: factsForFlow,
    evidenceSteps: buildEvidenceSteps(factsForFlow),
    aiExplanation: aiExplanation || undefined,
  };
}

function parseRootFacts(root: Record<string, unknown>): EvidenceLocation[] {
  return asArray(root.evidence_facts)
    .map(parseEvidenceLocation)
    .filter((item): item is EvidenceLocation => item !== undefined);
}

/** Parse analyze-file --json output. */
export function parseAnalyzeFileJson(payload: unknown): ScanResult {
  const root = asRecord(payload);
  if (!root) {
    throw new Error("Analyzer returned invalid JSON (expected an object).");
  }

  const source = asRecord(root.source);
  const fallbackFile = asString(source?.path);
  const rootFacts = parseRootFacts(root);
  const findings = asArray(root.findings).map((item, index) => {
    const record = asRecord(item);
    if (!record) {
      throw new Error(`Analyzer finding at index ${index} is not an object.`);
    }
    return buildFinding(record, index, fallbackFile, rootFacts);
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

export function confidenceIcon(confidence: Confidence): string {
  switch (String(confidence).toLowerCase()) {
    case "high":
      return "🔴";
    case "medium":
      return "🟠";
    default:
      return "🔵";
  }
}

export function formatSidebarFindingLabel(finding: SecurityFinding): string {
  return `${confidenceIcon(finding.confidence)} ${formatFindingLabel(finding)}`;
}

export function formatDiagnosticMessage(finding: SecurityFinding): string {
  const why =
    finding.explanation.trim() ||
    "Potential security issue indicated by the deterministic analyzer.";
  const fix =
    finding.remediation?.trim() ||
    finding.recommendations[0]?.trim() ||
    "Review the flagged code path and apply a safer control.";

  return [
    formatFindingLabel(finding),
    "",
    "Why:",
    why,
    "",
    "Fix:",
    fix,
    "",
    'Click "View Security Finding" for full details.',
  ].join("\n");
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

export function findFindingById(
  findings: SecurityFinding[],
  id: string,
): SecurityFinding | undefined {
  return findings.find((finding) => finding.id === id);
}
