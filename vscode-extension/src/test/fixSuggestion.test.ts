/** Tests for AI fix-suggestion parsing and rendering helpers. */

import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { buildFindingDetailModel, formatFindingDetailMarkdown } from "../detailView";
import { buildEvidenceSteps } from "../evidenceFlow";
import {
  FIX_SAFETY_LABEL,
  formatFixSuggestionSection,
  parseFixSuggestionPayload,
} from "../fixSuggestion";
import type { SecurityFinding } from "../types";

function sampleFinding(): SecurityFinding {
  const evidence = [
    {
      kind: "database_query",
      attrs: {},
      location: {
        path: "users.py",
        line: 5,
        snippet: 'cursor.execute("SELECT * FROM users WHERE id = " + user_id)',
      },
    },
  ];
  return {
    id: "users.py:5:sql_injection:0",
    issueType: "sql_injection",
    displayName: "SQL Injection",
    confidence: "high",
    file: "users.py",
    line: 5,
    column: 4,
    snippet: evidence[0].location?.snippet,
    explanation: "Unsafe SQL construction.",
    recommendations: ["Use parameterized queries"],
    remediation: "Use parameterized queries",
    evidenceLocations: evidence,
    evidenceSteps: buildEvidenceSteps(evidence),
  };
}

describe("parseFixSuggestionPayload", () => {
  it("parses a valid suggestion payload", () => {
    const payload = parseFixSuggestionPayload({
      available: true,
      suggestion: {
        kind: "ai_fix_suggestion",
        issue_type: "sql_injection",
        summary: "Bind the user id as a query parameter.",
        replacement_code:
          'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
        explanation: "Parameter binding keeps input out of SQL syntax.",
        warnings: ["Review before applying."],
        disclaimer: FIX_SAFETY_LABEL,
      },
      source_snippet: 'cursor.execute("SELECT * FROM users WHERE id = " + user_id)',
      finding: {
        issue_type: "sql_injection",
        confidence: "high",
      },
    });
    assert.equal(payload.available, true);
    assert.equal(payload.suggestion?.issueType, "sql_injection");
    assert.match(payload.suggestion?.replacementCode ?? "", /%s/);
  });

  it("treats unavailable payloads as graceful fallback", () => {
    const payload = parseFixSuggestionPayload({
      available: false,
      message: "AI fix suggestion unavailable.",
      suggestion: null,
      finding: { issue_type: "sql_injection", confidence: "high" },
    });
    assert.equal(payload.available, false);
    assert.equal(payload.suggestion, null);
    assert.equal(payload.message, "AI fix suggestion unavailable.");
    assert.equal(payload.finding?.issueType, "sql_injection");
  });

  it("rejects malformed suggestion bodies", () => {
    const payload = parseFixSuggestionPayload({
      available: true,
      suggestion: {
        issue_type: "sql_injection",
        summary: "",
        replacement_code: "",
        explanation: "",
      },
    });
    assert.equal(payload.available, false);
    assert.equal(payload.suggestion, null);
  });
});

describe("fix suggestion rendering", () => {
  it("formats the suggestion section for the detail view", () => {
    const text = formatFixSuggestionSection({
      summary: "Use parameter binding.",
      replacementCode: 'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
      explanation: "Keeps untrusted input out of SQL syntax.",
      warnings: ["Not guaranteed secure."],
      disclaimer: FIX_SAFETY_LABEL,
      issueType: "sql_injection",
    });
    assert.match(text, /AI Fix Suggestion/);
    assert.match(text, /Review before applying/);
    assert.match(text, /parameter binding/i);
    assert.match(text, /%s/);
  });

  it("renders suggestion and current-vs-suggested blocks in markdown", () => {
    const model = buildFindingDetailModel(sampleFinding(), {
      fixStatus: "available",
      sourceSnippet: 'cursor.execute("SELECT * FROM users WHERE id = " + user_id)',
      fixSuggestion: {
        summary: "Bind the user id.",
        replacementCode:
          'cursor.execute(\n    "SELECT * FROM users WHERE id = %s",\n    (user_id,),\n)',
        explanation: "Parameter binding prevents SQL syntax injection.",
        warnings: ["Review before applying."],
        disclaimer: FIX_SAFETY_LABEL,
        issueType: "sql_injection",
      },
    });
    const markdown = formatFindingDetailMarkdown(model);
    assert.match(markdown, /AI Fix Suggestion/);
    assert.match(markdown, /Current Code/);
    assert.match(markdown, /Suggested Code/);
    assert.match(markdown, /%s/);
  });

  it("renders unavailable fallback without inventing a suggestion", () => {
    const model = buildFindingDetailModel(sampleFinding(), {
      fixStatus: "unavailable",
      fixMessage: "AI fix suggestion unavailable.",
    });
    const markdown = formatFindingDetailMarkdown(model);
    assert.match(markdown, /AI fix suggestion unavailable/);
    assert.doesNotMatch(markdown, /Suggested replacement/);
  });
});
