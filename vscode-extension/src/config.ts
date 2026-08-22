/** VS Code configuration helpers. */

import * as vscode from "vscode";

export function getExecutablePath(): string {
  const value = vscode.workspace
    .getConfiguration("aiSecurityAssistant")
    .get<string>("executablePath", "ai-security-assistant");
  return (value || "ai-security-assistant").trim();
}

export function getScanOnSave(): boolean {
  return vscode.workspace
    .getConfiguration("aiSecurityAssistant")
    .get<boolean>("scanOnSave", false);
}
