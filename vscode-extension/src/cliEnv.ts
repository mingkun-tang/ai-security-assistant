/** CLI subprocess environment helpers (no VS Code dependency). */

export const DEFAULT_OPENAI_MODEL = "gpt-4o-mini";

/**
 * Build environment for CLI subprocesses.
 * Preserves an existing OPENAI_MODEL in the parent environment;
 * otherwise forwards the configured model (default gpt-4o-mini).
 */
export function buildCliEnvironment(
  baseEnv: NodeJS.ProcessEnv,
  configuredModel: string,
): NodeJS.ProcessEnv {
  const env = { ...baseEnv };
  if (!env.OPENAI_MODEL?.trim()) {
    env.OPENAI_MODEL = (configuredModel || DEFAULT_OPENAI_MODEL).trim();
  }
  return env;
}
