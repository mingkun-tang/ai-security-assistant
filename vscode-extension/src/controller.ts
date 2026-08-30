/** Orchestrates CLI scans and updates VS Code UI surfaces. */

import * as vscode from "vscode";
import {
  APPLY_CONFIRM_TITLE,
  APPLY_SAFETY_LABEL,
  FIX_APPLIED_RESCAN_FAILED_MESSAGE,
  STALE_SOURCE_MESSAGE,
  buildApplyFixPlan,
  findingStillPresent,
  resolveApplyDecision,
  rescanOutcomeMessage,
} from "./applyFix";
import { CliError, analyzeFileJson, scanProjectJson, suggestFixJson } from "./cli";
import { getExecutablePath } from "./config";
import {
  applyDiagnostics,
  clearFindingDiagnosticIndex,
  findingIdForDiagnostic,
} from "./diagnostics";
import { FindingDetailPanel } from "./findingDetailPanel";
import {
  findFindingById,
  parseAnalyzeFileJson,
  parseJsonText,
  parseScanJson,
} from "./findings";
import { parseFixSuggestionPayload } from "./fixSuggestion";
import { resolveFindingUri } from "./paths";
import type { FindingsStatusBar } from "./statusBar";
import type { FindingsTreeProvider } from "./treeView";
import type { SecurityFinding } from "./types";

export class FindingsController {
  private findings: SecurityFinding[] = [];

  constructor(
    private readonly diagnostics: vscode.DiagnosticCollection,
    private readonly tree: FindingsTreeProvider,
    private readonly statusBar: FindingsStatusBar,
  ) {}

  clear(): void {
    this.findings = [];
    this.diagnostics.clear();
    clearFindingDiagnosticIndex();
    this.tree.setFindings([]);
    this.statusBar.setCount(0);
  }

  setFindings(findings: SecurityFinding[]): void {
    this.findings = findings;
    const folder = vscode.workspace.workspaceFolders?.[0];
    applyDiagnostics(this.diagnostics, findings, (file) =>
      resolveFindingUri(file, folder),
    );
    this.tree.setFindings(findings);
    this.statusBar.setCount(findings.length);
  }

  getFindings(): SecurityFinding[] {
    return this.findings;
  }

  /** Resolve a Problems diagnostic back to the live finding for Quick Fix / detail view. */
  findingForDiagnostic(
    uri: vscode.Uri,
    diagnostic: vscode.Diagnostic,
  ): SecurityFinding | undefined {
    const id = findingIdForDiagnostic(uri, diagnostic);
    if (id) {
      const byId = findFindingById(this.findings, id);
      if (byId) {
        return byId;
      }
    }
    const line = diagnostic.range.start.line + 1;
    const issueType = String(diagnostic.code ?? "");
    return this.findings.find((finding) => {
      if (finding.line !== line) {
        return false;
      }
      if (issueType && finding.issueType !== issueType) {
        return false;
      }
      const folder = vscode.workspace.workspaceFolders?.[0];
      const findingUri = resolveFindingUri(finding.file, folder);
      return findingUri?.toString() === uri.toString();
    });
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
    await this.viewFindingDetails(finding);
  }

  async viewFindingDetails(finding?: SecurityFinding): Promise<void> {
    const selected = finding ?? (await this.pickFinding());
    if (!selected) {
      return;
    }

    FindingDetailPanel.show(selected, {
      generateFixHandler: (item) => this.generateFixSuggestion(item),
      applyFixHandler: (item) => this.applySuggestedFix(item),
    });
    await this.revealFindingInEditor(selected);
  }

  private panelHandlers() {
    return {
      generateFixHandler: (item: SecurityFinding) =>
        this.generateFixSuggestion(item),
      applyFixHandler: (item: SecurityFinding) => this.applySuggestedFix(item),
      preserveState: true as const,
    };
  }

  async generateFixSuggestion(finding?: SecurityFinding): Promise<void> {
    const selected =
      finding ??
      FindingDetailPanel.currentPanel()?.getFinding() ??
      (await this.pickFinding());
    if (!selected) {
      return;
    }

    const folder = vscode.workspace.workspaceFolders?.[0];
    const uri = resolveFindingUri(selected.file, folder);
    if (!uri) {
      void vscode.window.showWarningMessage(
        `Could not resolve file for finding: ${selected.file}`,
      );
      return;
    }

    const panel = FindingDetailPanel.show(selected, this.panelHandlers());
    panel.setLoading();

    const executable = getExecutablePath();
    try {
      const raw = await suggestFixJson(
        executable,
        uri.fsPath,
        selected.issueType,
        selected.line,
      );
      const payload = parseFixSuggestionPayload(raw);
      if (!payload.available || !payload.suggestion) {
        panel.setUnavailable(
          payload.message || "AI fix suggestion unavailable.",
        );
        return;
      }

      // Guard: AI must not change the deterministic issue type.
      if (payload.suggestion.issueType !== selected.issueType) {
        panel.setUnavailable("AI fix suggestion unavailable.");
        return;
      }

      panel.setSuggestion(
        payload.suggestion,
        payload.sourceSnippet || selected.snippet,
      );
    } catch (error) {
      panel.setUnavailable("AI fix suggestion unavailable.");
      if (error instanceof CliError && error.message.includes("not found")) {
        this.handleError(error);
      }
    }
  }

  async applySuggestedFix(finding?: SecurityFinding): Promise<void> {
    let selected =
      finding ?? FindingDetailPanel.currentPanel()?.getFinding() ?? undefined;
    if (!selected) {
      selected = await this.pickFinding();
    }
    if (!selected) {
      return;
    }

    // Re-bind handlers so Apply works even if the panel was opened earlier
    // without applyFixHandler (packaged VSIX / command-palette path).
    const panel = FindingDetailPanel.show(selected, this.panelHandlers());
    const state = panel.getState();
    const suggestion = state.fixSuggestion;
    const expectedSnippet =
      state.sourceSnippet?.trimEnd() || selected.snippet?.trimEnd() || "";

    if (!suggestion?.replacementCode?.trim()) {
      void vscode.window.showWarningMessage(
        "No validated fix suggestion is available to apply. Generate one from the finding panel first.",
      );
      return;
    }
    if (!expectedSnippet) {
      void vscode.window.showWarningMessage(
        "Fix suggestion is missing the original source snippet.",
      );
      return;
    }

    const folder = vscode.workspace.workspaceFolders?.[0];
    const uri = resolveFindingUri(selected.file, folder);
    if (!uri) {
      void vscode.window.showWarningMessage(
        `Could not resolve file for finding: ${selected.file}`,
      );
      return;
    }

    // Do NOT open untitled vscode.diff here. In Cursor/VS Code that preview
    // can show Keep/Undo controls that do not write the real source file.
    // Apply must use WorkspaceEdit against the real document URI only.

    const choice = await vscode.window.showWarningMessage(
      `${APPLY_CONFIRM_TITLE}\n\n${APPLY_SAFETY_LABEL}\n\nOnly the matched snippet range will be replaced. You can undo with normal Editor: Undo.`,
      { modal: true },
      "Apply Fix",
    );
    if (resolveApplyDecision(choice) !== "apply") {
      return;
    }

    let document: vscode.TextDocument;
    try {
      document = await vscode.workspace.openTextDocument(uri);
    } catch (error) {
      void vscode.window.showErrorMessage(
        `Could not open file for editing: ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
      return;
    }

    const plan = buildApplyFixPlan({
      documentText: document.getText(),
      expectedSnippet,
      replacementCode: suggestion.replacementCode,
      preferredLine: selected.line,
    });
    if (!plan.ok) {
      void vscode.window.showWarningMessage(plan.message);
      if (
        plan.reason === "stale_source" ||
        plan.reason === "snippet_not_found"
      ) {
        panel.setUnavailable(STALE_SOURCE_MESSAGE);
      }
      return;
    }

    const latestText = document.getText();
    const recheck = buildApplyFixPlan({
      documentText: latestText,
      expectedSnippet,
      replacementCode: suggestion.replacementCode,
      preferredLine: selected.line,
    });
    if (
      !recheck.ok ||
      recheck.range.startOffset !== plan.range.startOffset ||
      recheck.range.endOffset !== plan.range.endOffset ||
      recheck.replacement !== plan.replacement
    ) {
      const message = !recheck.ok ? recheck.message : STALE_SOURCE_MESSAGE;
      void vscode.window.showWarningMessage(message);
      panel.setUnavailable(message);
      return;
    }

    const start = document.positionAt(recheck.range.startOffset);
    const end = document.positionAt(recheck.range.endOffset);
    const edit = new vscode.WorkspaceEdit();
    edit.replace(document.uri, new vscode.Range(start, end), recheck.replacement);

    const applied = await vscode.workspace.applyEdit(edit);
    if (!applied) {
      void vscode.window.showErrorMessage(
        "Could not apply the suggested fix. The file may be read-only.",
      );
      return;
    }

    // Reveal the real file so the user sees the WorkspaceEdit, not a preview buffer.
    const replacementEnd = document.positionAt(
      recheck.range.startOffset + recheck.replacement.length,
    );
    const editor = await vscode.window.showTextDocument(document, {
      preview: false,
      viewColumn: vscode.ViewColumn.One,
      selection: new vscode.Range(start, replacementEnd),
    });
    editor.revealRange(
      editor.selection,
      vscode.TextEditorRevealType.InCenterIfOutsideViewport,
    );

    panel.clearSuggestion();
    await this.rescanAfterApply(selected, document.uri);
  }

  private async rescanAfterApply(
    previous: SecurityFinding,
    uri: vscode.Uri,
  ): Promise<void> {
    const executable = getExecutablePath();
    try {
      // Ensure analyzer sees buffer contents if unsaved.
      const document = await vscode.workspace.openTextDocument(uri);
      if (document.isDirty) {
        await document.save();
      }

      const raw = await analyzeFileJson(executable, uri.fsPath);
      const result =
        typeof raw === "string"
          ? parseAnalyzeFileJson(parseJsonText(raw))
          : parseAnalyzeFileJson(raw);

      // Refresh UI for this file's findings while preserving other workspace findings.
      const remaining = this.findings.filter((item) => {
        const itemUri = resolveFindingUri(
          item.file,
          vscode.workspace.workspaceFolders?.[0],
        );
        return !itemUri || itemUri.toString() !== uri.toString();
      });
      this.setFindings([...remaining, ...result.findings]);

      const stillThere = findingStillPresent(
        result.findings.map((item) => ({
          issueType: item.issueType,
          line: item.line,
        })),
        previous.issueType,
        previous.line,
      );

      if (stillThere) {
        void vscode.window.showInformationMessage(
          rescanOutcomeMessage(true),
        );
      } else {
        void vscode.window.showInformationMessage(
          rescanOutcomeMessage(false),
        );
      }
    } catch (error) {
      void vscode.window.showWarningMessage(
        FIX_APPLIED_RESCAN_FAILED_MESSAGE,
      );
      if (error instanceof CliError) {
        this.handleError(error);
      }
    }
  }

  async revealFindingInEditor(finding: SecurityFinding): Promise<void> {
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
      viewColumn: vscode.ViewColumn.One,
    });
    editor.revealRange(
      new vscode.Range(line, 0, line, 0),
      vscode.TextEditorRevealType.InCenter,
    );
  }

  private async pickFinding(): Promise<SecurityFinding | undefined> {
    if (!this.findings.length) {
      void vscode.window.showInformationMessage(
        "No security findings to view. Run a scan first.",
      );
      return undefined;
    }

    const picked = await vscode.window.showQuickPick(
      this.findings.map((finding) => ({
        label: `${finding.displayName} — ${finding.confidence}`,
        description:
          finding.line != null
            ? `${finding.file}:${finding.line}`
            : finding.file,
        finding,
      })),
      { placeHolder: "Select a security finding" },
    );
    return picked?.finding;
  }

  resolveFinding(idOrFinding: string | SecurityFinding): SecurityFinding | undefined {
    if (typeof idOrFinding !== "string") {
      return idOrFinding;
    }
    return findFindingById(this.findings, idOrFinding);
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
