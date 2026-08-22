/** Webview panel for polished finding details + optional AI fix suggestions. */

import * as vscode from "vscode";
import {
  buildFindingDetailModel,
  renderFindingDetailHtml,
  type DetailViewState,
} from "./detailView";
import type { FixSuggestion, SecurityFinding } from "./types";

export class FindingDetailPanel {
  public static readonly viewType = "aiSecurityAssistant.findingDetail";

  private static current: FindingDetailPanel | undefined;

  private readonly panel: vscode.WebviewPanel;
  private finding: SecurityFinding;
  private state: DetailViewState = { fixStatus: "idle" };
  private generateFixHandler?: (finding: SecurityFinding) => Promise<void>;

  private constructor(panel: vscode.WebviewPanel, finding: SecurityFinding) {
    this.panel = panel;
    this.finding = finding;
    this.render();

    this.panel.webview.onDidReceiveMessage(async (message) => {
      if (!message || typeof message.command !== "string") {
        return;
      }
      if (message.command === "generateFix") {
        if (this.generateFixHandler) {
          await this.generateFixHandler(this.finding);
        }
        return;
      }
      if (message.command === "showDiff") {
        await this.showDiffPreview();
      }
    });

    this.panel.onDidDispose(() => {
      if (FindingDetailPanel.current === this) {
        FindingDetailPanel.current = undefined;
      }
    });
  }

  static show(
    finding: SecurityFinding,
    options?: {
      generateFixHandler?: (finding: SecurityFinding) => Promise<void>;
    },
  ): FindingDetailPanel {
    const column = vscode.ViewColumn.Beside;

    if (FindingDetailPanel.current) {
      FindingDetailPanel.current.finding = finding;
      FindingDetailPanel.current.state = { fixStatus: "idle" };
      if (options?.generateFixHandler) {
        FindingDetailPanel.current.generateFixHandler = options.generateFixHandler;
      }
      FindingDetailPanel.current.render();
      FindingDetailPanel.current.panel.reveal(column, true);
      return FindingDetailPanel.current;
    }

    const panel = vscode.window.createWebviewPanel(
      FindingDetailPanel.viewType,
      `Security: ${finding.displayName}`,
      column,
      {
        enableScripts: true,
        retainContextWhenHidden: true,
      },
    );

    FindingDetailPanel.current = new FindingDetailPanel(panel, finding);
    if (options?.generateFixHandler) {
      FindingDetailPanel.current.generateFixHandler = options.generateFixHandler;
    }
    return FindingDetailPanel.current;
  }

  static currentPanel(): FindingDetailPanel | undefined {
    return FindingDetailPanel.current;
  }

  getFinding(): SecurityFinding {
    return this.finding;
  }

  setLoading(): void {
    this.state = {
      ...this.state,
      fixStatus: "loading",
      fixMessage: undefined,
      fixSuggestion: undefined,
    };
    this.render();
  }

  setSuggestion(
    suggestion: FixSuggestion,
    sourceSnippet?: string,
  ): void {
    this.state = {
      fixStatus: "available",
      fixSuggestion: suggestion,
      sourceSnippet: sourceSnippet || this.state.sourceSnippet,
      fixMessage: undefined,
    };
    this.render();
  }

  setUnavailable(message = "AI fix suggestion unavailable."): void {
    this.state = {
      ...this.state,
      fixStatus: "unavailable",
      fixSuggestion: undefined,
      fixMessage: message,
    };
    this.render();
  }

  private async showDiffPreview(): Promise<void> {
    const suggestion = this.state.fixSuggestion;
    if (!suggestion) {
      return;
    }
    const current = this.state.sourceSnippet || this.finding.snippet || "";
    const left = await vscode.workspace.openTextDocument({
      content: current || "(current snippet unavailable)\n",
      language: "python",
    });
    const right = await vscode.workspace.openTextDocument({
      content: suggestion.replacementCode + "\n",
      language: "python",
    });
    await vscode.commands.executeCommand(
      "vscode.diff",
      left.uri,
      right.uri,
      `Current ↔ Suggested (${this.finding.displayName})`,
    );
  }

  private render(): void {
    const model = buildFindingDetailModel(this.finding, this.state);
    this.panel.title = `Security: ${model.issue}`;
    this.panel.webview.html = renderFindingDetailHtml(model);
  }
}
