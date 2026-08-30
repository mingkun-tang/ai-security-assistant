/** Shared UI strings/constants (no vscode runtime dependency). */

export const DIAGNOSTIC_SOURCE = "AI Security Assistant";

export const VIEW_SECURITY_FINDING_TITLE = "View Security Finding";

export const VIEW_FINDING_DETAILS_COMMAND =
  "aiSecurityAssistant.viewFindingDetails";

export const DIAGNOSTIC_DETAILS_GUIDANCE =
  "Open the AI Security Assistant sidebar, or use Quick Fix → View Security Finding for full details.";

export function quickFixTitlesForDiagnostics(
  diagnostics: ReadonlyArray<{ source?: string }>,
  source = DIAGNOSTIC_SOURCE,
): string[] {
  return diagnostics
    .filter((diagnostic) => diagnostic.source === source)
    .map(() => VIEW_SECURITY_FINDING_TITLE);
}

export function buildFindingNodeCommand<T>(finding: T): {
  command: string;
  title: string;
  arguments: [T];
} {
  return {
    command: VIEW_FINDING_DETAILS_COMMAND,
    title: "View Finding Details",
    arguments: [finding],
  };
}
