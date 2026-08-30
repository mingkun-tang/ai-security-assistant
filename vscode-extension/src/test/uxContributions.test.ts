/** Contribution / UX wiring tests for Activity Bar + Quick Fix guidance. */

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import { describe, it } from "node:test";
import {
  formatDiagnosticMessage,
  parseAnalyzeFileJson,
} from "../findings";
import {
  DIAGNOSTIC_SOURCE,
  VIEW_SECURITY_FINDING_TITLE,
  buildFindingNodeCommand,
  quickFixTitlesForDiagnostics,
} from "../uiConstants";

const PKG = JSON.parse(
  readFileSync(path.join(__dirname, "..", "..", "package.json"), "utf8"),
) as {
  contributes: {
    viewsContainers?: { activitybar?: Array<{ id: string; icon: string }> };
    views?: Record<string, Array<{ id: string; name: string }>>;
    viewsWelcome?: Array<{ view: string; contents: string }>;
    commands?: Array<{ command: string }>;
  };
  activationEvents?: string[];
};

const ANALYZE_FILE_SAMPLE = {
  source: { path: "/tmp/users.py", language: "python" },
  findings: [
    {
      issue_type: "sql_injection",
      display_name: "SQL Injection",
      confidence: "high",
      missing_control:
        "The application may be constructing SQL queries using user-controlled input.",
      impact: "Attackers may read or modify database records.",
      recommendations: [
        "Use parameterized or prepared statements for all database access",
        "Never concatenate user input into SQL strings",
      ],
      evidence_locations: [
        {
          id: "F1",
          kind: "input_source",
          attrs: { channel: "query", name: "id" },
          location: {
            path: "/tmp/users.py",
            line: 4,
            column: 14,
            snippet: 'request.args.get("id")',
          },
        },
        {
          id: "F2",
          kind: "database_query",
          attrs: {
            construction: "concat",
            uses_input_source_ids: ["F1"],
          },
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

describe("package contributions for sidebar UX", () => {
  it("declares an Activity Bar container with an SVG icon", () => {
    const containers = PKG.contributes.viewsContainers?.activitybar ?? [];
    assert.equal(containers.length, 1);
    assert.equal(containers[0]?.id, "ai-security-assistant");
    assert.match(containers[0]?.icon ?? "", /media\/icon\.svg$/);
  });

  it("registers the Findings view inside that container", () => {
    const views = PKG.contributes.views?.["ai-security-assistant"] ?? [];
    assert.equal(views.length, 1);
    assert.equal(views[0]?.id, "aiSecurityAssistant.findings");
    assert.match(views[0]?.name ?? "", /Findings/i);
  });

  it("activates on the Findings view and registers detail command", () => {
    assert.ok(
      (PKG.activationEvents ?? []).includes(
        "onView:aiSecurityAssistant.findings",
      ),
    );
    const commands = (PKG.contributes.commands ?? []).map((c) => c.command);
    assert.ok(commands.includes("aiSecurityAssistant.viewFindingDetails"));
    assert.ok(commands.includes("aiSecurityAssistant.focusFindings"));
  });

  it("provides a welcome view for empty findings", () => {
    const welcome = PKG.contributes.viewsWelcome ?? [];
    assert.ok(
      welcome.some((entry) => entry.view === "aiSecurityAssistant.findings"),
    );
  });

  it("uses a mask-friendly filled Activity Bar SVG (not stroke-only)", () => {
    const svg = readFileSync(
      path.join(__dirname, "..", "..", "media", "icon.svg"),
      "utf8",
    );
    assert.match(svg, /fill="#ffffff"|fill='#ffffff'|fill="white"/i);
    assert.doesNotMatch(svg, /stroke="/);
  });
});

describe("diagnostic guidance matches available UI", () => {
  it("points users to the sidebar and Quick Fix, not a missing hover link", () => {
    const finding = parseAnalyzeFileJson(ANALYZE_FILE_SAMPLE).findings[0];
    const message = formatDiagnosticMessage(finding);
    assert.match(message, /AI Security Assistant sidebar/i);
    assert.match(message, /Quick Fix/i);
    assert.match(message, /View Security Finding/);
    assert.doesNotMatch(
      message,
      /Click "View Security Finding" for full details/,
    );
  });

  it("exposes View Security Finding as a Quick Fix title for our diagnostics", () => {
    const titles = quickFixTitlesForDiagnostics([
      { source: DIAGNOSTIC_SOURCE },
      { source: "eslint" },
    ]);
    assert.deepEqual(titles, [VIEW_SECURITY_FINDING_TITLE]);
  });
});

describe("findings tree opens detail command", () => {
  it("wires finding click to viewFindingDetails", () => {
    const finding = parseAnalyzeFileJson(ANALYZE_FILE_SAMPLE).findings[0];
    const command = buildFindingNodeCommand(finding);
    assert.equal(command.command, "aiSecurityAssistant.viewFindingDetails");
    assert.deepEqual(command.arguments, [finding]);
  });
});
