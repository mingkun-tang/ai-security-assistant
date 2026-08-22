/** Pure diagnostic severity mapping tests (mirrors VS Code severity ranks). */

import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { confidenceToSeverityRank } from "../findings";

function mapSeverity(confidence: string): "error" | "warning" | "info" {
  const rank = confidenceToSeverityRank(confidence);
  if (rank >= 3) {
    return "error";
  }
  if (rank === 2) {
    return "warning";
  }
  return "info";
}

describe("diagnostic severity mapping", () => {
  it("maps high → error, medium → warning, low → info", () => {
    assert.equal(mapSeverity("high"), "error");
    assert.equal(mapSeverity("medium"), "warning");
    assert.equal(mapSeverity("low"), "info");
    assert.equal(mapSeverity("unknown"), "info");
  });
});
