/** Detail view, evidence flow, and remediation tests. */

import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  AI_EXPLANATION_DISCLAIMER,
  buildFindingDetailModel,
  formatFindingDetailMarkdown,
  formatRemediationSection,
  renderFindingDetailHtml,
} from "../detailView";
import {
  buildEvidenceSteps,
  formatEvidenceFlow,
  labelForEvidenceFact,
} from "../evidenceFlow";
import { parseAnalyzeFileJson } from "../findings";
import type { EvidenceLocation, SecurityFinding } from "../types";

function sampleFinding(overrides: Partial<SecurityFinding> = {}): SecurityFinding {
  const evidence: EvidenceLocation[] = [
    {
      id: "F1",
      kind: "input_source",
      attrs: { channel: "query", name: "id" },
      location: {
        path: "users.py",
        line: 4,
        snippet: 'request.args.get("id")',
      },
    },
    {
      id: "F2",
      kind: "database_query",
      attrs: { construction: "concat", uses_input_source_ids: ["F1"] },
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
    snippet: evidence[1].location?.snippet,
    explanation:
      "User-controlled input reaches an SQL query through string concatenation.",
    impact: "Attackers may read or modify database records.",
    remediation: "Use parameterized SQL queries instead of string concatenation.",
    recommendations: [
      "Use parameterized SQL queries instead of string concatenation.",
      "Never concatenate user input into SQL strings",
    ],
    evidenceLocations: evidence,
    evidenceSteps: buildEvidenceSteps(evidence),
    ...overrides,
  };
}

describe("evidence flow", () => {
  it("labels input and sink facts", () => {
    const input: EvidenceLocation = {
      kind: "input_source",
      attrs: { channel: "query", name: "url" },
      location: { snippet: 'request.args.get("url")' },
    };
    const sink: EvidenceLocation = {
      kind: "network_request",
      attrs: { destination_kind: "from_input" },
      location: { snippet: "requests.get(url)" },
    };
    assert.equal(labelForEvidenceFact(input), "User-Controlled URL");
    assert.equal(labelForEvidenceFact(sink), "Server Request");
  });

  it("formats a textual source → sink flow", () => {
    const steps = buildEvidenceSteps(sampleFinding().evidenceLocations);
    const flow = formatEvidenceFlow(steps);
    assert.match(flow, /User Input/);
    assert.match(flow, /request\.args\.get\("id"\)/);
    assert.match(flow, /↓/);
    assert.match(flow, /Database Query/);
    assert.match(flow, /cursor\.execute/);
  });

  it("formats SSRF-style flows", () => {
    const facts: EvidenceLocation[] = [
      {
        kind: "input_source",
        attrs: { channel: "query", name: "url" },
        location: { snippet: 'request.args.get("url")' },
      },
      {
        kind: "network_request",
        attrs: { destination_kind: "from_input" },
        location: { snippet: "requests.get(url)" },
      },
    ];
    const flow = formatEvidenceFlow(buildEvidenceSteps(facts));
    assert.match(flow, /User-Controlled URL/);
    assert.match(flow, /requests\.get\(url\)/);
  });
});

describe("detail-view model", () => {
  it("constructs a deterministic detail model", () => {
    const model = buildFindingDetailModel(sampleFinding());
    assert.equal(model.issue, "SQL Injection");
    assert.equal(model.confidenceLabel, "High");
    assert.equal(model.file, "users.py");
    assert.equal(model.line, 5);
    assert.equal(model.evidenceSteps.length, 2);
    assert.match(model.whyFlagged, /string concatenation/);
    assert.match(model.impact, /database/);
    assert.match(model.primaryRemediation ?? "", /parameterized/i);
    assert.equal(model.additionalRemediations.length, 1);
    assert.equal(model.showAiSection, false);
    assert.equal(model.aiExplanation, undefined);
  });

  it("includes AI explanation only when present", () => {
    const withAi = buildFindingDetailModel(
      sampleFinding({
        aiExplanation: "This looks like classic SQLi via query concatenation.",
      }),
    );
    assert.equal(withAi.showAiSection, true);
    assert.match(withAi.aiExplanation ?? "", /classic SQLi/);
    assert.equal(withAi.aiDisclaimer, AI_EXPLANATION_DISCLAIMER);

    const markdown = formatFindingDetailMarkdown(withAi);
    assert.match(markdown, /## AI Explanation/);
    assert.match(markdown, /does not determine/);

    const withoutAi = formatFindingDetailMarkdown(buildFindingDetailModel(sampleFinding()));
    assert.doesNotMatch(withoutAi, /## AI Explanation/);
  });

  it("renders remediation prominently", () => {
    const model = buildFindingDetailModel(sampleFinding());
    const section = formatRemediationSection(model);
    assert.match(section, /Recommended Fix/);
    assert.match(section, /parameterized SQL queries/);
    assert.match(section, /Additional guidance/);

    const html = renderFindingDetailHtml(model);
    assert.match(html, /Recommended Fix/);
    assert.match(html, /class="fix"/);
    assert.doesNotMatch(html, /AI Explanation/);
  });

  it("keeps AI visually separate in HTML when present", () => {
    const html = renderFindingDetailHtml(
      buildFindingDetailModel(
        sampleFinding({ aiExplanation: "Optional narrative only." }),
      ),
    );
    assert.match(html, /class="ai"/);
    assert.match(html, /Optional narrative only/);
    assert.match(html, /source of truth/);
  });
});

describe("navigation helpers via parse", () => {
  it("preserves enough fields for detail navigation", () => {
    const finding = parseAnalyzeFileJson({
      source: { path: "/tmp/users.py" },
      findings: [
        {
          issue_type: "sql_injection",
          display_name: "SQL Injection",
          confidence: "high",
          missing_control: "Unsafe query construction.",
          impact: "Data exposure.",
          recommendations: ["Use parameterized queries"],
          evidence_locations: [
            {
              kind: "database_query",
              location: { path: "/tmp/users.py", line: 9, column: 2, snippet: "execute(q)" },
            },
          ],
        },
      ],
    }).findings[0];

    const model = buildFindingDetailModel(finding);
    assert.equal(model.file, "/tmp/users.py");
    assert.equal(model.line, 9);
    assert.equal(model.primaryRemediation, "Use parameterized queries");
  });
});
