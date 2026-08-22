/** VS Code extension entry point. */

import * as vscode from "vscode";
import { getScanOnSave } from "./config";
import { FindingsController } from "./controller";
import { FindingsStatusBar } from "./statusBar";
import { FindingsTreeProvider } from "./treeView";
import type { SecurityFinding } from "./types";

export function activate(context: vscode.ExtensionContext): void {
  const diagnostics = vscode.languages.createDiagnosticCollection(
    "aiSecurityAssistant",
  );
  const tree = new FindingsTreeProvider();
  const statusBar = new FindingsStatusBar();
  const controller = new FindingsController(diagnostics, tree, statusBar);

  const treeView = vscode.window.createTreeView("aiSecurityAssistant.findings", {
    treeDataProvider: tree,
    showCollapseAll: true,
  });

  context.subscriptions.push(
    diagnostics,
    statusBar,
    treeView,
    vscode.commands.registerCommand(
      "aiSecurityAssistant.scanCurrentFile",
      () => controller.scanCurrentFile(),
    ),
    vscode.commands.registerCommand(
      "aiSecurityAssistant.scanWorkspace",
      () => controller.scanWorkspace(),
    ),
    vscode.commands.registerCommand(
      "aiSecurityAssistant.clearFindings",
      () => {
        controller.clear();
        void vscode.window.showInformationMessage("Cleared security findings.");
      },
    ),
    vscode.commands.registerCommand(
      "aiSecurityAssistant.focusFindings",
      async () => {
        await vscode.commands.executeCommand(
          "aiSecurityAssistant.findings.focus",
        );
      },
    ),
    vscode.commands.registerCommand(
      "aiSecurityAssistant.openFinding",
      (finding: SecurityFinding) => controller.openFinding(finding),
    ),
    vscode.commands.registerCommand(
      "aiSecurityAssistant.viewFindingDetails",
      (finding?: SecurityFinding) => controller.viewFindingDetails(finding),
    ),
    vscode.commands.registerCommand(
      "aiSecurityAssistant.generateFixSuggestion",
      (finding?: SecurityFinding) => controller.generateFixSuggestion(finding),
    ),
    vscode.commands.registerCommand(
      "aiSecurityAssistant.applySuggestedFix",
      (finding?: SecurityFinding) => controller.applySuggestedFix(finding),
    ),
    vscode.workspace.onDidSaveTextDocument((document) => {
      if (!getScanOnSave()) {
        return;
      }
      if (document.languageId !== "python" && !document.fileName.endsWith(".py")) {
        return;
      }
      const active = vscode.window.activeTextEditor?.document;
      if (active !== document) {
        return;
      }
      void controller.scanCurrentFile();
    }),
  );
}

export function deactivate(): void {
  // Disposals are handled via subscriptions.
}
