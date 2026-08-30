/** Quick Fix actions for AI Security Assistant diagnostics. */

import * as vscode from "vscode";
import type { SecurityFinding } from "./types";
import {
  DIAGNOSTIC_SOURCE,
  VIEW_SECURITY_FINDING_TITLE,
} from "./uiConstants";

export {
  DIAGNOSTIC_SOURCE,
  VIEW_SECURITY_FINDING_TITLE,
  quickFixTitlesForDiagnostics,
} from "./uiConstants";

export type FindingLookup = (
  uri: vscode.Uri,
  diagnostic: vscode.Diagnostic,
) => SecurityFinding | undefined;

/**
 * Exposes "View Security Finding" in the Quick Fix menu for our diagnostics.
 * Hover text cannot attach custom command links; Quick Fix is the supported surface.
 */
export class FindingCodeActionProvider implements vscode.CodeActionProvider {
  constructor(private readonly lookupFinding: FindingLookup) {}

  provideCodeActions(
    document: vscode.TextDocument,
    _range: vscode.Range | vscode.Selection,
    context: vscode.CodeActionContext,
  ): vscode.CodeAction[] {
    const actions: vscode.CodeAction[] = [];
    for (const diagnostic of context.diagnostics) {
      if (diagnostic.source !== DIAGNOSTIC_SOURCE) {
        continue;
      }
      const finding = this.lookupFinding(document.uri, diagnostic);
      if (!finding) {
        continue;
      }
      const action = new vscode.CodeAction(
        VIEW_SECURITY_FINDING_TITLE,
        vscode.CodeActionKind.QuickFix,
      );
      action.diagnostics = [diagnostic];
      action.isPreferred = true;
      action.command = {
        command: "aiSecurityAssistant.viewFindingDetails",
        title: VIEW_SECURITY_FINDING_TITLE,
        arguments: [finding],
      };
      actions.push(action);
    }
    return actions;
  }
}
