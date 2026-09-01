/** VS Code configuration helpers. */

import * as vscode from "vscode";
import { DEFAULT_OPENAI_MODEL } from "./cliEnv";
import { resolveExecutablePath } from "./executablePath";

export { DEFAULT_OPENAI_MODEL } from "./cliEnv";
export {
  ExecutablePathError,
  WORKSPACE_FOLDER_VARIABLE,
  resolveExecutablePath,
} from "./executablePath";

export function getExecutablePath(): string {
  const value = vscode.workspace
    .getConfiguration("aiSecurityAssistant")
    .get<string>("executablePath", "ai-security-assistant");
  const workspaceFolder = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
  return resolveExecutablePath(value ?? "ai-security-assistant", workspaceFolder);
}

export function getScanOnSave(): boolean {
  return vscode.workspace
    .getConfiguration("aiSecurityAssistant")
    .get<boolean>("scanOnSave", false);
}

export function getOpenAiModel(): string {
  const value = vscode.workspace
    .getConfiguration("aiSecurityAssistant")
    .get<string>("openaiModel", DEFAULT_OPENAI_MODEL);
  const trimmed = (value || DEFAULT_OPENAI_MODEL).trim();
  return trimmed || DEFAULT_OPENAI_MODEL;
}
