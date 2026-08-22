/** Orchestrates CLI scans and updates VS Code UI surfaces. */

import * as vscode from "vscode";
import { CliError, analyzeFileJson, scanProjectJson } from "./cli";
import { getExecutablePath } from "./config";
import { applyDiagnostics } from "./diagnostics";
import {
  parseAnalyzeFileJson,
  parseJsonText,
  parseScanJson,
} from "./findings";
import { resolveFindingUri } from "./paths";
import type { FindingsStatusBar } from "./statusBar";
import type { FindingsTreeProvider } from "./treeView";
import type { SecurityFinding } from "./types";

export class FindingsController {
  constructor(
    private readonly diagnostics: vscode.DiagnosticCollection,
    private readonly tree: FindingsTreeProvider,
    private readonly statusBar: FindingsStatusBar,
  ) {}

  clear(): void {
    this.diagnostics.clear();
    this.tree.setFindings([]);
    this.statusBar.setCount(0);
  }

  setFindings(findings: SecurityFinding[]): void {
    const folder = vscode.workspace.workspaceFolders?.[0];
    applyDiagnostics(this.diagnostics, findings, (file) =>
      resolveFindingUri(file, folder),
    );
    this.tree.setFindings(findings);
    this.statusBar.setCount(findings.length);
  }

  async scanCurrentFile(): Promise<void> {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
      void vscode.window.showInformationMessage(
        "Open a Python file to scan.",
      );
      return;
    }

    const document = editor.document;
    if (document.languageId !== "python" && !document.fileName.endsWith(".py")) {
      void vscode.window.showInformationMessage(
        "AI Security Assistant currently supports Python files only.",
      );
      return;
    }

    if (document.isUntitled) {
      void vscode.window.showWarningMessage(
        "Save the file before scanning.",
      );
      return;
    }

    if (document.isDirty) {
      const saved = await document.save();
      if (!saved) {
        void vscode.window.showWarningMessage(
          "Could not save the current file before scanning.",
        );
        return;
      }
    }

    const executable = getExecutablePath();
    await vscode.window.withProgress(
      {
        location: vscode.ProgressLocation.Notification,
        title: "AI Security Assistant: scanning file…",
        cancellable: false,
      },
      async () => {
        try {
          const raw = await analyzeFileJson(executable, document.fileName);
          // analyzeFileJson already parses; re-parse path for typed errors from text path
          const result =
            typeof raw === "string"
              ? parseAnalyzeFileJson(parseJsonText(raw))
              : parseAnalyzeFileJson(raw);
          this.setFindings(result.findings);
          if (result.findings.length === 0) {
            void vscode.window.showInformationMessage(
              "No security findings in the current file.",
            );
          } else {
            void vscode.window.showInformationMessage(
              `Found ${result.findings.length} security finding${result.findings.length === 1 ? "" : "s"}.`,
            );
          }
        } catch (error) {
          this.handleError(error);
        }
      },
    );
  }

  async scanWorkspace(): Promise<void> {
    const folder = vscode.workspace.workspaceFolders?.[0];
    if (!folder) {
      void vscode.window.showWarningMessage(
        "Open a workspace folder to scan a project.",
      );
      return;
    }

    const executable = getExecutablePath();
    await vscode.window.withProgress(
      {
        location: vscode.ProgressLocation.Notification,
        title: "AI Security Assistant: scanning workspace…",
        cancellable: false,
      },
      async () => {
        try {
          const raw = await scanProjectJson(executable, folder.uri.fsPath);
          const result =
            typeof raw === "string"
              ? parseScanJson(parseJsonText(raw))
              : parseScanJson(raw);
          this.setFindings(result.findings);
          const analyzed = result.filesAnalyzed;
          if (result.findings.length === 0) {
            void vscode.window.showInformationMessage(
              analyzed != null
                ? `Scanned ${analyzed} file${analyzed === 1 ? "" : "s"}; no findings.`
                : "No security findings in the workspace.",
            );
          } else {
            void vscode.window.showInformationMessage(
              `Found ${result.findings.length} security finding${result.findings.length === 1 ? "" : "s"}${
                analyzed != null ? ` across ${analyzed} files` : ""
              }.`,
            );
          }
        } catch (error) {
          this.handleError(error);
        }
      },
    );
  }

  async openFinding(finding: SecurityFinding): Promise<void> {
    const folder = vscode.workspace.workspaceFolders?.[0];
    const uri = resolveFindingUri(finding.file, folder);
    if (!uri) {
      void vscode.window.showWarningMessage(
        `Could not resolve file for finding: ${finding.file}`,
      );
      return;
    }

    const document = await vscode.workspace.openTextDocument(uri);
    const line = Math.max(0, (finding.line ?? 1) - 1);
    const column = Math.max(0, (finding.column ?? 1) - 1);
    const editor = await vscode.window.showTextDocument(document, {
      preview: true,
      selection: new vscode.Range(line, column, line, column),
    });
    editor.revealRange(
      new vscode.Range(line, 0, line, 0),
      vscode.TextEditorRevealType.InCenter,
    );
  }

  private handleError(error: unknown): void {
    if (error instanceof CliError) {
      const stderr = error.details?.stderr?.trim();
      void vscode.window.showErrorMessage(
        stderr ? `${error.message} ${stderr}` : error.message,
      );
      return;
    }
    if (error instanceof SyntaxError) {
      void vscode.window.showErrorMessage(
        `Analyzer returned invalid JSON: ${error.message}`,
      );
      return;
    }
    if (error instanceof Error) {
      void vscode.window.showErrorMessage(error.message);
      return;
    }
    void vscode.window.showErrorMessage(`Unexpected scan error: ${String(error)}`);
  }
}
