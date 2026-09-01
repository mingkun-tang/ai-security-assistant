/** Resolve configured analyzer executable paths for the extension. */

export const WORKSPACE_FOLDER_VARIABLE = "${workspaceFolder}";

export class ExecutablePathError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ExecutablePathError";
  }
}

/** Expand ${workspaceFolder} in a configured analyzer path. */
export function resolveExecutablePath(
  configuredPath: string,
  workspaceFolderPath?: string,
): string {
  const trimmed = (configuredPath || "ai-security-assistant").trim();

  if (!trimmed.includes(WORKSPACE_FOLDER_VARIABLE)) {
    return trimmed;
  }

  if (!workspaceFolderPath) {
    throw new ExecutablePathError(
      `aiSecurityAssistant.executablePath uses ${WORKSPACE_FOLDER_VARIABLE} but no workspace folder is open. ` +
        "Open a folder in VS Code or set an absolute path to the analyzer executable.",
    );
  }

  return trimmed.split(WORKSPACE_FOLDER_VARIABLE).join(workspaceFolderPath);
}
