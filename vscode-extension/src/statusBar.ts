/** Status bar item for finding counts. */

import * as vscode from "vscode";

export class FindingsStatusBar {
  private readonly item: vscode.StatusBarItem;

  constructor() {
    this.item = vscode.window.createStatusBarItem(
      vscode.StatusBarAlignment.Left,
      100,
    );
    this.item.command = "aiSecurityAssistant.focusFindings";
    this.item.tooltip = "AI Security Assistant findings";
    this.setCount(0);
    this.item.show();
  }

  setCount(count: number): void {
    this.item.text =
      count === 0
        ? "Security: 0 findings"
        : `Security: ${count} finding${count === 1 ? "" : "s"}`;
  }

  dispose(): void {
    this.item.dispose();
  }
}
