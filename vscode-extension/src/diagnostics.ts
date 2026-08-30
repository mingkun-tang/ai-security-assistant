/** Map SecurityFinding records to VS Code diagnostics. */

import * as vscode from "vscode";
import {
  confidenceToSeverityRank,
  formatDiagnosticMessage,
} from "./findings";
import type { Confidence, SecurityFinding } from "./types";
import { DIAGNOSTIC_SOURCE } from "./uiConstants";

export { DIAGNOSTIC_SOURCE } from "./uiConstants";

/** Side index so CodeActions can resolve a diagnostic back to a finding id. */
const findingIdByDiagnosticKey = new Map<string, string>();

export function diagnosticLookupKey(
  uri: vscode.Uri,
  diagnostic: vscode.Diagnostic,
): string {
  return [
    uri.toString(),
    diagnostic.range.start.line,
    diagnostic.range.start.character,
    String(diagnostic.code ?? ""),
    diagnostic.message,
  ].join("\u0000");
}

export function rememberFindingDiagnostic(
  uri: vscode.Uri,
  diagnostic: vscode.Diagnostic,
  findingId: string,
): void {
  findingIdByDiagnosticKey.set(
    diagnosticLookupKey(uri, diagnostic),
    findingId,
  );
}

export function clearFindingDiagnosticIndex(): void {
  findingIdByDiagnosticKey.clear();
}

export function findingIdForDiagnostic(
  uri: vscode.Uri,
  diagnostic: vscode.Diagnostic,
): string | undefined {
  return findingIdByDiagnosticKey.get(diagnosticLookupKey(uri, diagnostic));
}

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
  clearFindingDiagnosticIndex();
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
    const diagnostic = findingToDiagnostic(finding);
    rememberFindingDiagnostic(uri, diagnostic, finding.id);
    list.push(diagnostic);
    byUri.set(key, list);
  }

  for (const [key, diagnostics] of byUri) {
    collection.set(vscode.Uri.parse(key), diagnostics);
  }
}
