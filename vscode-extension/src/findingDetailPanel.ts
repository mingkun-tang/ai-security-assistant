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
  private applyFixHandler?: (finding: SecurityFinding) => Promise<void>;

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
        return;
      }
      if (message.command === "applyFix") {
        if (this.applyFixHandler) {
          await this.applyFixHandler(this.finding);
        }
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
      applyFixHandler?: (finding: SecurityFinding) => Promise<void>;
      preserveState?: boolean;
    },
  ): FindingDetailPanel {
    const column = vscode.ViewColumn.Beside;

    if (FindingDetailPanel.current) {
      FindingDetailPanel.current.finding = finding;
      if (!options?.preserveState) {
        FindingDetailPanel.current.state = { fixStatus: "idle" };
      }
      if (options?.generateFixHandler) {
        FindingDetailPanel.current.generateFixHandler = options.generateFixHandler;
      }
      if (options?.applyFixHandler) {
        FindingDetailPanel.current.applyFixHandler = options.applyFixHandler;
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
    if (options?.applyFixHandler) {
      FindingDetailPanel.current.applyFixHandler = options.applyFixHandler;
    }
    return FindingDetailPanel.current;
  }

  static currentPanel(): FindingDetailPanel | undefined {
    return FindingDetailPanel.current;
  }

  getFinding(): SecurityFinding {
    return this.finding;
  }

  getState(): DetailViewState {
    return this.state;
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

  clearSuggestion(message?: string): void {
    this.state = {
      fixStatus: message ? "unavailable" : "idle",
      fixSuggestion: undefined,
      fixMessage: message,
      sourceSnippet: this.state.sourceSnippet,
    };
    this.render();
  }

  async showDiffPreview(): Promise<void> {
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
      `Preview only · Current ↔ Suggested (${this.finding.displayName})`,
    );
    void vscode.window.showInformationMessage(
      "Diff preview does not modify your file. Click Apply Suggested Fix in the finding panel to write the change.",
    );
  }

  private render(): void {
    const model = buildFindingDetailModel(this.finding, this.state);
    this.panel.title = `Security: ${model.issue}`;
    this.panel.webview.html = renderFindingDetailHtml(model);
  }
}
