"""Language-neutral evidence observations. Parsers record facts; they do not classify."""

from __future__ import annotations

from dataclasses import dataclass, field, fields


SCHEMA_VERSION = "1"

FACT_KINDS = (
    "input_source",
    "database_query",
    "rendered_output",
    "network_request",
    "file_upload",
    "auth_context",
    "data_access",
    "authorization_check",
)

CLASSIFICATION_FIELD_NAMES = frozenset(
    {
        "issue_type",
        "findings",
        "confidence",
        "vulnerability_indicated",
        "remediation",
        "recommendations",
    }
)


@dataclass
class Location:
    id: str
    path: str
    line: int | None = None
    column: int | None = None
    snippet: str | None = None


@dataclass
class SourceUnit:
    path: str
    language: str


@dataclass
class Fact:
    id: str
    kind: str
    location_id: str
    attrs: dict = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)


@dataclass
class EvidenceDocument:
    schema_version: str = SCHEMA_VERSION
    language: str = ""
    units: list[SourceUnit] = field(default_factory=list)
    facts: list[Fact] = field(default_factory=list)
    locations: list[Location] = field(default_factory=list)


def empty_document(*, language: str, path: str) -> EvidenceDocument:
    """Return an observation document with no facts."""

    return EvidenceDocument(
        schema_version=SCHEMA_VERSION,
        language=language,
        units=[SourceUnit(path=path, language=language)],
        facts=[],
        locations=[],
    )


def model_field_names() -> set[str]:
    names: set[str] = set()
    for model in (Location, SourceUnit, Fact, EvidenceDocument):
        names.update(item.name for item in fields(model))
    return names
