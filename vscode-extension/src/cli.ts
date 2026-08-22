/** Invoke the local AI Security Assistant CLI. */

import { spawn } from "child_process";

export interface CliRunResult {
  stdout: string;
  stderr: string;
  code: number | null;
}

export class CliError extends Error {
  constructor(
    message: string,
    readonly details?: { code?: number | null; stderr?: string },
  ) {
    super(message);
    this.name = "CliError";
  }
}

export async function runCli(
  executable: string,
  args: string[],
  options: { cwd?: string; timeoutMs?: number } = {},
): Promise<CliRunResult> {
  const timeoutMs = options.timeoutMs ?? 120_000;

  return new Promise((resolve, reject) => {
    let settled = false;
    const child = spawn(executable, args, {
      cwd: options.cwd,
      env: process.env,
      shell: false,
    });

    let stdout = "";
    let stderr = "";

    const timer = setTimeout(() => {
      if (!settled) {
        settled = true;
        child.kill("SIGTERM");
        reject(
          new CliError(
            `Analyzer timed out after ${Math.round(timeoutMs / 1000)}s.`,
          ),
        );
      }
    }, timeoutMs);

    child.stdout.on("data", (chunk: Buffer | string) => {
      stdout += chunk.toString();
    });
    child.stderr.on("data", (chunk: Buffer | string) => {
      stderr += chunk.toString();
    });

    child.on("error", (error: NodeJS.ErrnoException) => {
      if (settled) {
        return;
      }
      settled = true;
      clearTimeout(timer);
      if (error.code === "ENOENT") {
        reject(
          new CliError(
            `Analyzer executable not found: "${executable}". ` +
              "Install the CLI or set aiSecurityAssistant.executablePath.",
          ),
        );
        return;
      }
      reject(new CliError(`Failed to start analyzer: ${error.message}`));
    });

    child.on("close", (code) => {
      if (settled) {
        return;
      }
      settled = true;
      clearTimeout(timer);
      resolve({ stdout, stderr, code });
    });
  });
}

export async function analyzeFileJson(
  executable: string,
  filePath: string,
  options: { cwd?: string } = {},
): Promise<unknown> {
  const result = await runCli(executable, ["analyze-file", filePath, "--json"], options);
  if (result.code !== 0) {
    throw new CliError(
      `analyze-file failed (exit ${result.code ?? "unknown"}).`,
      { code: result.code, stderr: result.stderr },
    );
  }
  return parseCliJson(result.stdout);
}

export async function scanProjectJson(
  executable: string,
  projectPath: string,
  options: { cwd?: string } = {},
): Promise<unknown> {
  const result = await runCli(executable, ["scan", projectPath, "--json"], options);
  if (result.code !== 0) {
    throw new CliError(
      `scan failed (exit ${result.code ?? "unknown"}).`,
      { code: result.code, stderr: result.stderr },
    );
  }
  return parseCliJson(result.stdout);
}

export async function suggestFixJson(
  executable: string,
  filePath: string,
  issueType: string,
  line: number | null | undefined,
  options: { cwd?: string; timeoutMs?: number } = {},
): Promise<unknown> {
  const args = ["suggest-fix", filePath, "--issue", issueType, "--json"];
  if (line != null) {
    args.push("--line", String(line));
  }
  const result = await runCli(executable, args, {
    cwd: options.cwd,
    timeoutMs: options.timeoutMs ?? 90_000,
  });
  // Unavailable AI still returns exit 0 with available:false JSON.
  if (result.code !== 0) {
    throw new CliError(
      `suggest-fix failed (exit ${result.code ?? "unknown"}).`,
      { code: result.code, stderr: result.stderr },
    );
  }
  return parseCliJson(result.stdout);
}

function parseCliJson(stdout: string): unknown {
  const text = stdout.trim();
  if (!text) {
    throw new CliError("Analyzer returned empty output instead of JSON.");
  }
  try {
    return JSON.parse(text);
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    throw new CliError(`Analyzer returned invalid JSON: ${detail}`, {
      stderr: text.slice(0, 500),
    });
  }
}
