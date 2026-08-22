/** Unit tests for JSON parsing and finding helpers (no VS Code runtime). */

import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  confidenceToSeverityRank,
  formatDiagnosticMessage,
  formatFindingLabel,
  groupFindingsByFile,
  parseAnalyzeFileJson,
  parseJsonText,
  parseScanJson,
} from "../findings";

const ANALYZE_FILE_SAMPLE = {
  source: { path: "/tmp/users.py", language: "python" },
  findings: [
    {
      issue_type: "sql_injection",
      display_name: "SQL Injection",
      confidence: "high",
      missing_control:
        "The application may be constructing SQL queries using user-controlled input.",
      recommendations: [
        "Use parameterized or prepared statements for all database access",
        "Never concatenate user input into SQL strings",
      ],
      evidence_locations: [
        {
          kind: "database_query",
          location: {
            path: "/tmp/users.py",
            line: 12,
            column: 4,
            snippet: 'cursor.execute("SELECT " + q)',
          },
        },
      ],
    },
  ],
};

const SCAN_SAMPLE = {
  project: "./demo",
  files_analyzed: 2,
  findings: [
    {
      issue_type: "ssrf",
      display_name: "Server-Side Request Forgery (SSRF)",
      confidence: "high",
      file: "./app/api/fetch.py",
      line: 6,
      column: 4,
      snippet: "requests.get(url)",
      missing_control: "User-controlled URL reaches a server-side request.",
      recommendations: ["Validate and allowlist outbound destinations"],
    },
    {
      issue_type: "sql_injection",
      display_name: "SQL Injection",
      confidence: "high",
      file: "./app/routes/users.py",
      line: 5,
      column: 4,
      missing_control: "Unsafe SQL construction.",
      recommendations: ["Use parameterized queries"],
    },
  ],
};

describe("parseAnalyzeFileJson", () => {
  it("maps file findings with location and remediation", () => {
    const result = parseAnalyzeFileJson(ANALYZE_FILE_SAMPLE);
    assert.equal(result.findings.length, 1);
    const finding = result.findings[0];
    assert.equal(finding.displayName, "SQL Injection");
    assert.equal(finding.confidence, "high");
    assert.equal(finding.file, "/tmp/users.py");
    assert.equal(finding.line, 12);
    assert.equal(finding.column, 4);
    assert.match(finding.explanation, /SQL queries/i);
    assert.match(finding.remediation ?? "", /parameterized/i);
  });

  it("rejects non-object payloads", () => {
    assert.throws(() => parseAnalyzeFileJson([]), /invalid JSON/i);
  });
});

describe("parseScanJson", () => {
  it("maps aggregated workspace findings", () => {
    const result = parseScanJson(SCAN_SAMPLE);
    assert.equal(result.filesAnalyzed, 2);
    assert.equal(result.findings.length, 2);
    assert.equal(result.findings[0].issueType, "ssrf");
    assert.equal(result.findings[0].file, "./app/api/fetch.py");
    assert.equal(result.findings[1].line, 5);
  });
});

describe("parseJsonText", () => {
  it("parses valid JSON", () => {
    assert.deepEqual(parseJsonText('{"ok": true}'), { ok: true });
  });

  it("throws a clear error for invalid JSON", () => {
    assert.throws(() => parseJsonText("{"), /invalid JSON/i);
  });
});

describe("formatting and grouping", () => {
  it("formats labels and diagnostic messages", () => {
    const finding = parseAnalyzeFileJson(ANALYZE_FILE_SAMPLE).findings[0];
    assert.equal(formatFindingLabel(finding), "SQL Injection — High");
    const message = formatDiagnosticMessage(finding);
    assert.match(message, /SQL Injection — High/);
    assert.match(message, /parameterized/i);
  });

  it("groups findings by file", () => {
    const findings = parseScanJson(SCAN_SAMPLE).findings;
    const groups = groupFindingsByFile(findings);
    assert.equal(groups.size, 2);
    assert.equal(groups.get("./app/api/fetch.py")?.length, 1);
  });

  it("ranks confidence for severity mapping", () => {
    assert.equal(confidenceToSeverityRank("high"), 3);
    assert.equal(confidenceToSeverityRank("medium"), 2);
    assert.equal(confidenceToSeverityRank("low"), 1);
  });
});
