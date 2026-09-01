/** Tests for configuration defaults and CLI environment forwarding. */

import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  DEFAULT_OPENAI_MODEL,
  buildCliEnvironment,
} from "../cliEnv";
import {
  ExecutablePathError,
  WORKSPACE_FOLDER_VARIABLE,
  resolveExecutablePath,
} from "../executablePath";

describe("executable path resolution", () => {
  it("expands ${workspaceFolder} in configured paths", () => {
    const resolved = resolveExecutablePath(
      `${WORKSPACE_FOLDER_VARIABLE}/.venv/bin/ai-security-assistant`,
      "/tmp/project",
    );
    assert.equal(
      resolved,
      "/tmp/project/.venv/bin/ai-security-assistant",
    );
  });

  it("leaves absolute paths unchanged", () => {
    const absolute =
      "/Users/example/Appsec Projects/ai-security-assistant/.venv/bin/ai-security-assistant";
    assert.equal(resolveExecutablePath(absolute, "/tmp/project"), absolute);
  });

  it("leaves bare command names unchanged", () => {
    assert.equal(resolveExecutablePath("ai-security-assistant"), "ai-security-assistant");
  });

  it("throws when ${workspaceFolder} is used without an open workspace folder", () => {
    assert.throws(
      () =>
        resolveExecutablePath(
          `${WORKSPACE_FOLDER_VARIABLE}/.venv/bin/ai-security-assistant`,
        ),
      (error: unknown) => {
        assert.ok(error instanceof ExecutablePathError);
        assert.match(
          (error as Error).message,
          /no workspace folder is open/i,
        );
        return true;
      },
    );
  });
});

describe("OpenAI model configuration", () => {
  it("uses gpt-4o-mini as the documented default", () => {
    assert.equal(DEFAULT_OPENAI_MODEL, "gpt-4o-mini");
  });

  it("forwards the VS Code setting as OPENAI_MODEL when env is unset", () => {
    const env = buildCliEnvironment({}, DEFAULT_OPENAI_MODEL);
    assert.equal(env.OPENAI_MODEL, "gpt-4o-mini");
  });

  it("forwards a custom configured model when env is unset", () => {
    const env = buildCliEnvironment({}, "gpt-4o");
    assert.equal(env.OPENAI_MODEL, "gpt-4o");
  });

  it("preserves an existing OPENAI_MODEL environment override", () => {
    const env = buildCliEnvironment(
      { OPENAI_MODEL: "custom-from-shell" },
      "gpt-4o-mini",
    );
    assert.equal(env.OPENAI_MODEL, "custom-from-shell");
  });

  it("treats blank OPENAI_MODEL in the parent env as unset", () => {
    const env = buildCliEnvironment({ OPENAI_MODEL: "   " }, "gpt-4o-mini");
    assert.equal(env.OPENAI_MODEL, "gpt-4o-mini");
  });

  it("does not remove unrelated environment variables", () => {
    const env = buildCliEnvironment(
      { PATH: "/usr/bin", OPENAI_API_KEY: "sk-test" },
      DEFAULT_OPENAI_MODEL,
    );
    assert.equal(env.PATH, "/usr/bin");
    assert.equal(env.OPENAI_API_KEY, "sk-test");
    assert.equal(env.OPENAI_MODEL, "gpt-4o-mini");
  });
});
