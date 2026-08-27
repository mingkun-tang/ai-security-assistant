/** Tests for configuration defaults and CLI environment forwarding. */

import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  DEFAULT_OPENAI_MODEL,
  buildCliEnvironment,
} from "../cliEnv";

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
