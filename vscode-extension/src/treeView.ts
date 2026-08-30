/** Findings TreeView grouped by file. */

import * as path from "path";
import * as vscode from "vscode";
import {
  formatFindingLabel,
  formatSidebarFindingLabel,
  groupFindingsByFile,
} from "./findings";
import type { SecurityFinding } from "./types";
import { buildFindingNodeCommand } from "./uiConstants";

export { buildFindingNodeCommand } from "./uiConstants";

export type FindingsTreeNode = FileNode | FindingNode;

export class FileNode extends vscode.TreeItem {
  constructor(
    readonly filePath: string,
    readonly findings: SecurityFinding[],
  ) {
    super(path.basename(filePath), vscode.TreeItemCollapsibleState.Expanded);
    this.contextValue = "aiSecurityFile";
    this.description = `${findings.length}`;
    this.tooltip = filePath;
    this.iconPath = new vscode.ThemeIcon("file-code");
  }
}

export class FindingNode extends vscode.TreeItem {
  constructor(readonly finding: SecurityFinding) {
    super(
      formatSidebarFindingLabel(finding),
      vscode.TreeItemCollapsibleState.None,
    );
    this.contextValue = "aiSecurityFinding";
    this.tooltip = [
      formatFindingLabel(finding),
      finding.explanation,
      finding.remediation ? `Fix: ${finding.remediation}` : undefined,
    ]
      .filter(Boolean)
      .join("\n\n");
    this.description = finding.line != null ? `L${finding.line}` : undefined;
    this.iconPath = new vscode.ThemeIcon(
      String(finding.confidence).toLowerCase() === "high"
        ? "error"
        : String(finding.confidence).toLowerCase() === "medium"
          ? "warning"
          : "info",
    );
    this.command = buildFindingNodeCommand(finding);
  }
}

export class FindingsTreeProvider
  implements vscode.TreeDataProvider<FindingsTreeNode>
{
  private readonly _onDidChangeTreeData =
    new vscode.EventEmitter<FindingsTreeNode | undefined | null | void>();
  readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

  private findings: SecurityFinding[] = [];

  setFindings(findings: SecurityFinding[]): void {
    this.findings = findings;
    this._onDidChangeTreeData.fire();
  }

  getFindings(): SecurityFinding[] {
    return this.findings;
  }

  getTreeItem(element: FindingsTreeNode): vscode.TreeItem {
    return element;
  }

  getChildren(element?: FindingsTreeNode): FindingsTreeNode[] {
    if (!element) {
      const groups = groupFindingsByFile(this.findings);
      return [...groups.entries()]
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([file, items]) => new FileNode(file, items));
    }
    if (element instanceof FileNode) {
      return element.findings.map((finding) => new FindingNode(finding));
    }
    return [];
  }
}
