/** Map SecurityFinding records to VS Code diagnostics. */

import * as vscode from "vscode";
import {
  confidenceToSeverityRank,
  formatDiagnosticMessage,
} from "./findings";
import type { Confidence, SecurityFinding } from "./types";

export const DIAGNOSTIC_SOURCE = "AI Security Assistant";

export function confidenceToDiagnosticSeverity(
  confidence: Confidence,
): vscode.DiagnosticSeverity {
  switch (String(confidence).toLowerCase()) {
    case "high":
      return vscode.DiagnosticSeverity.Error;
    case "medium":
      return vscode.DiagnosticSeverity.Warning;
    default:
      return vscode.DiagnosticSeverity.Information;
  }
}

export function findingToDiagnostic(finding: SecurityFinding): vscode.Diagnostic {
  const line = Math.max(0, (finding.line ?? 1) - 1);
  const column = Math.max(0, (finding.column ?? 1) - 1);
  const range = new vscode.Range(line, column, line, Number.MAX_SAFE_INTEGER);
  const diagnostic = new vscode.Diagnostic(
    range,
    formatDiagnosticMessage(finding),
    confidenceToDiagnosticSeverity(finding.confidence),
  );
  diagnostic.source = DIAGNOSTIC_SOURCE;
  diagnostic.code = finding.issueType;
  return diagnostic;
}

export function applyDiagnostics(
  collection: vscode.DiagnosticCollection,
  findings: SecurityFinding[],
  resolveUri: (file: string) => vscode.Uri | undefined,
): void {
  collection.clear();
  const byUri = new Map<string, vscode.Diagnostic[]>();

  const sorted = [...findings].sort(
    (a, b) =>
      confidenceToSeverityRank(b.confidence) -
      confidenceToSeverityRank(a.confidence),
  );

  for (const finding of sorted) {
    const uri = resolveUri(finding.file);
    if (!uri) {
      continue;
    }
    const key = uri.toString();
    const list = byUri.get(key) ?? [];
    list.push(findingToDiagnostic(finding));
    byUri.set(key, list);
  }

  for (const [key, diagnostics] of byUri) {
    collection.set(vscode.Uri.parse(key), diagnostics);
  }
}
