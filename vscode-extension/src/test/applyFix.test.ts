/** Tests for apply-fix planning, stale checks, and confirmation decisions. */

import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  APPLY_CONFIRM_TITLE,
  STALE_SOURCE_MESSAGE,
  alignReplacementIndent,
  buildApplyFixPlan,
  findingStillPresent,
  findSnippetRange,
  resolveApplyDecision,
  verifySnippetStillMatches,
} from "../applyFix";
import { buildFindingDetailModel, renderFindingDetailHtml } from "../detailView";
import { buildEvidenceSteps } from "../evidenceFlow";
import type { SecurityFinding } from "../types";

const ORIGINAL =
  '    cursor.execute("SELECT * FROM users WHERE id = " + user_id)';
const REPLACEMENT = `cursor.execute(
    "SELECT * FROM users WHERE id = %s",
    (user_id,),
)`;

function sampleDocument(snippet = ORIGINAL): string {
  return [
    "from flask import request",
    "",
    "def search():",
    '    user_id = request.args.get("id")',
    snippet,
    "",
  ].join("\n");
}

function sampleFinding(): SecurityFinding {
  const evidence = [
    {
      kind: "database_query",
      attrs: {},
      location: { path: "users.py", line: 5, snippet: ORIGINAL.trim() },
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
    snippet: ORIGINAL.trim(),
    explanation: "Unsafe SQL construction.",
    recommendations: ["Use parameterized queries"],
    evidenceLocations: evidence,
    evidenceSteps: buildEvidenceSteps(evidence),
  };
}

describe("apply fix planning", () => {
  it("constructs an exact-range replacement edit", () => {
    const documentText = sampleDocument();
    const plan = buildApplyFixPlan({
      documentText,
      expectedSnippet: ORIGINAL.trim(),
      replacementCode: REPLACEMENT,
      preferredLine: 5,
    });
    assert.equal(plan.ok, true);
    if (!plan.ok) {
      return;
    }
    assert.equal(plan.range.startLine, 4);
    assert.match(plan.range.matchedText, /cursor\.execute/);
    assert.match(plan.replacement, /^\s+cursor\.execute/);
    assert.match(plan.replacement, /%s/);

    const updated =
      documentText.slice(0, plan.range.startOffset) +
      plan.replacement +
      documentText.slice(plan.range.endOffset);
    assert.match(updated, /%s/);
    assert.doesNotMatch(updated, /\+ user_id/);
    assert.match(updated, /def search/);
  });

  it("rejects stale source that no longer matches the suggestion snippet", () => {
    const documentText = sampleDocument(
      '    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
    );
    const plan = buildApplyFixPlan({
      documentText,
      expectedSnippet: ORIGINAL.trim(),
      replacementCode: REPLACEMENT,
      preferredLine: 5,
    });
    assert.equal(plan.ok, false);
    if (plan.ok) {
      return;
    }
    assert.equal(plan.reason, "snippet_not_found");
    assert.equal(plan.message, STALE_SOURCE_MESSAGE);
  });

  it("rejects malformed suggestions with empty replacement code", () => {
    const plan = buildApplyFixPlan({
      documentText: sampleDocument(),
      expectedSnippet: ORIGINAL.trim(),
      replacementCode: "   ",
      preferredLine: 5,
    });
    assert.equal(plan.ok, false);
    if (plan.ok) {
      return;
    }
    assert.equal(plan.reason, "empty_replacement");
  });

  it("cancel decision causes no apply", () => {
    assert.equal(resolveApplyDecision(undefined), "cancel");
    assert.equal(resolveApplyDecision("Cancel"), "cancel");
    assert.equal(resolveApplyDecision("Apply Fix"), "apply");
    assert.match(APPLY_CONFIRM_TITLE, /AI-generated security fix/);
  });

  it("preserves indentation for multi-line replacements", () => {
    const aligned = alignReplacementIndent(ORIGINAL, REPLACEMENT, "\n");
    assert.match(aligned, /^ {4}cursor\.execute/);
    assert.match(aligned, /\n {8}\(user_id,\),/);
  });

  it("verifySnippetStillMatches detects in-place edits", () => {
    const documentText = sampleDocument();
    const range = findSnippetRange(documentText, ORIGINAL.trim(), 5);
    assert.ok(range);
    assert.equal(
      verifySnippetStillMatches(documentText, ORIGINAL.trim(), range!),
      true,
    );
    const mutated = documentText.replace("+ user_id", "+ changed");
    assert.equal(
      verifySnippetStillMatches(mutated, ORIGINAL.trim(), range!),
      false,
    );
  });
});

describe("rescan messaging helpers", () => {
  it("reports when the finding is no longer detected", () => {
    assert.equal(
      findingStillPresent([], "sql_injection", 5),
      false,
    );
  });

  it("reports when the finding remains after apply", () => {
    assert.equal(
      findingStillPresent(
        [{ issueType: "sql_injection", line: 5 }],
        "sql_injection",
        5,
      ),
      true,
    );
  });
});

describe("detail view apply button", () => {
  it("shows Apply Suggested Fix only when a suggestion exists", () => {
    const withSuggestion = renderFindingDetailHtml(
      buildFindingDetailModel(sampleFinding(), {
        fixStatus: "available",
        sourceSnippet: ORIGINAL.trim(),
        fixSuggestion: {
          summary: "Bind parameter",
          replacementCode: REPLACEMENT,
          explanation: "Safer query construction",
          warnings: [],
          disclaimer: "review",
          issueType: "sql_injection",
        },
      }),
    );
    assert.match(withSuggestion, /Apply Suggested Fix/);
    assert.match(withSuggestion, /id="apply-fix"/);

    const without = renderFindingDetailHtml(
      buildFindingDetailModel(sampleFinding(), { fixStatus: "idle" }),
    );
    assert.doesNotMatch(without, /id="apply-fix"/);
  });
});
