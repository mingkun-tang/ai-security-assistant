/** Evidence flow formatting from CLI observation facts (no detection logic). */

import type { EvidenceLocation, EvidenceStep } from "./types";

const KIND_LABELS: Record<string, string> = {
  input_source: "User Input",
  database_query: "Database Query",
  network_request: "Network Request",
  rendered_output: "Rendered Output",
  file_upload: "File Upload",
  data_access: "Data Access",
  authorization_check: "Authorization Check",
  auth_context: "Auth Context",
};

function titleKind(kind: string): string {
  return (
    KIND_LABELS[kind] ||
    kind
      .split("_")
      .filter(Boolean)
      .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
      .join(" ")
  );
}

function inputLabel(fact: EvidenceLocation): string {
  const channel = String(fact.attrs?.channel || "");
  const name = fact.attrs?.name ? String(fact.attrs.name) : undefined;
  if (channel.includes("url") || name === "url") {
    return "User-Controlled URL";
  }
  if (channel === "path" || channel === "query" || channel === "form" || channel === "json_body") {
    return name ? `User Input (${name})` : "User Input";
  }
  if (fact.kind === "input_source") {
    return "User Input";
  }
  return titleKind(fact.kind);
}

export function labelForEvidenceFact(fact: EvidenceLocation): string {
  if (fact.kind === "input_source") {
    return inputLabel(fact);
  }
  if (fact.kind === "network_request") {
    const destination = String(fact.attrs?.destination_kind || "");
    if (destination === "from_input" || (fact.attrs?.uses_input_source_ids as unknown[])?.length) {
      return "Server Request";
    }
  }
  return titleKind(fact.kind);
}

export function buildEvidenceSteps(facts: EvidenceLocation[]): EvidenceStep[] {
  if (!facts.length) {
    return [];
  }

  const steps: EvidenceStep[] = [];
  const seen = new Set<string>();

  for (const fact of facts) {
    const snippet = fact.location?.snippet?.trim();
    const key = `${fact.kind}:${snippet || fact.id || steps.length}`;
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);
    steps.push({
      label: labelForEvidenceFact(fact),
      kind: fact.kind,
      snippet: snippet || undefined,
      file: fact.location?.path,
      line: fact.location?.line ?? null,
    });
  }

  // Prefer source → sink ordering when mixed.
  const sources = steps.filter((step) =>
    ["input_source", "auth_context"].includes(step.kind),
  );
  const sinks = steps.filter(
    (step) => !["input_source", "auth_context"].includes(step.kind),
  );
  if (sources.length && sinks.length) {
    return [...sources, ...sinks];
  }
  return steps;
}

export function formatEvidenceFlow(steps: EvidenceStep[]): string {
  if (!steps.length) {
    return "";
  }

  const blocks: string[] = [];
  steps.forEach((step, index) => {
    blocks.push(step.label);
    if (step.snippet) {
      blocks.push(step.snippet);
    }
    if (index < steps.length - 1) {
      blocks.push("        ↓");
    }
  });
  return blocks.join("\n");
}
