/** Webview panel for polished finding details. */

import * as vscode from "vscode";
import {
  buildFindingDetailModel,
  renderFindingDetailHtml,
} from "./detailView";
import type { SecurityFinding } from "./types";

export class FindingDetailPanel {
  public static readonly viewType = "aiSecurityAssistant.findingDetail";

  private static current: FindingDetailPanel | undefined;

  private readonly panel: vscode.WebviewPanel;
  private finding: SecurityFinding;

  private constructor(panel: vscode.WebviewPanel, finding: SecurityFinding) {
    this.panel = panel;
    this.finding = finding;
    this.render();

    this.panel.onDidDispose(() => {
      if (FindingDetailPanel.current === this) {
        FindingDetailPanel.current = undefined;
      }
    });
  }

  static show(finding: SecurityFinding): FindingDetailPanel {
    const column = vscode.ViewColumn.Beside;

    if (FindingDetailPanel.current) {
      FindingDetailPanel.current.finding = finding;
      FindingDetailPanel.current.render();
      FindingDetailPanel.current.panel.reveal(column, true);
      return FindingDetailPanel.current;
    }

    const panel = vscode.window.createWebviewPanel(
      FindingDetailPanel.viewType,
      `Security: ${finding.displayName}`,
      column,
      {
        enableScripts: false,
        retainContextWhenHidden: true,
      },
    );

    FindingDetailPanel.current = new FindingDetailPanel(panel, finding);
    return FindingDetailPanel.current;
  }

  private render(): void {
    const model = buildFindingDetailModel(this.finding);
    this.panel.title = `Security: ${model.issue}`;
    this.panel.webview.html = renderFindingDetailHtml(model);
  }
}
