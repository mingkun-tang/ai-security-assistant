/** Path resolution helpers for CLI file references. */

import * as fs from "fs";
import * as path from "path";
import * as vscode from "vscode";

export function resolveFindingUri(
  file: string,
  workspaceFolder?: vscode.WorkspaceFolder,
): vscode.Uri | undefined {
  if (!file) {
    return undefined;
  }

  if (path.isAbsolute(file)) {
    return vscode.Uri.file(file);
  }

  const candidates: string[] = [];
  if (workspaceFolder) {
    candidates.push(path.resolve(workspaceFolder.uri.fsPath, file));
    candidates.push(
      path.resolve(workspaceFolder.uri.fsPath, file.replace(/^\.\//, "")),
    );
  }

  for (const folder of vscode.workspace.workspaceFolders ?? []) {
    candidates.push(path.resolve(folder.uri.fsPath, file));
    candidates.push(
      path.resolve(folder.uri.fsPath, file.replace(/^\.\//, "")),
    );
  }

  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) {
      return vscode.Uri.file(candidate);
    }
  }

  if (workspaceFolder) {
    return vscode.Uri.file(
      path.resolve(workspaceFolder.uri.fsPath, file.replace(/^\.\//, "")),
    );
  }

  return vscode.Uri.file(path.resolve(file.replace(/^\.\//, "")));
}

export function basenameLabel(file: string): string {
  return path.basename(file) || file || "unknown";
}
