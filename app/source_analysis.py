"""Analyze Python source files through the evidence pipeline."""

from __future__ import annotations

from pathlib import Path

from app.engine import analyze, build_structured_result
from app.parser.adapter import evidence_to_engine_input, facts_for_issue, serialize_fact
from app.parser.evidence import EvidenceDocument
from app.parser.python_parser import parse


def read_source_file(path: str | Path) -> tuple[str, str]:
    file_path = Path(path)
    source = file_path.read_text(encoding="utf-8")
    return str(file_path), source


def analyze_source(path: str | Path, *, language: str = "python") -> dict:
    """Parse a source file, run the deterministic engine, and enrich with locations."""

    file_path, source = read_source_file(path)
    evidence = parse(language, file_path, source)
    engine_input = evidence_to_engine_input(evidence)
    analysis = analyze(engine_input)
    report = build_structured_result(f"source: {file_path}", analysis)
    return enrich_source_report(report, evidence, file_path)


def enrich_source_report(
    report: dict,
    evidence: EvidenceDocument,
    file_path: str,
) -> dict:
    locations = {loc.id: loc for loc in evidence.locations}
    serialized_facts = [serialize_fact(fact, locations) for fact in evidence.facts]

    enriched = dict(report)
    enriched["source"] = {
        "path": file_path,
        "language": evidence.language,
    }
    enriched["evidence_facts"] = serialized_facts

    findings = []
    for finding in enriched.get("findings", []):
        item = dict(finding)
        item["evidence_locations"] = facts_for_issue(finding["issue_type"], evidence)
        findings.append(item)
    enriched["findings"] = findings
    return enriched
