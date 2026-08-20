"""Language-independent evidence pipeline. Parsers observe; the engine classifies."""

from app.parser.adapter import evidence_to_engine_input
from app.parser.evidence import (
    FACT_KINDS,
    EvidenceDocument,
    Fact,
    Location,
    SourceUnit,
)
from app.parser.python_parser import parse

__all__ = [
    "FACT_KINDS",
    "EvidenceDocument",
    "Fact",
    "Location",
    "SourceUnit",
    "evidence_to_engine_input",
    "parse",
]
