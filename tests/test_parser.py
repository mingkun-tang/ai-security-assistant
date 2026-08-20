from app.engine import analyze, empty_signals
from app.parser.adapter import evidence_to_engine_input
from app.parser.evidence import (
    CLASSIFICATION_FIELD_NAMES,
    EvidenceDocument,
    Fact,
    Location,
    SourceUnit,
    empty_document,
    model_field_names,
)
from app.parser.python_parser import parse


VALID_SOURCE = "x = 1\nprint(x)\n"
INVALID_SOURCE = "def (\n"
SQLI_LOOKING_SOURCE = """
def search(q):
    cursor.execute("SELECT * FROM users WHERE name = '%s'" % q)
"""


def test_valid_python_parses_successfully():
    doc = parse("python", "example.py", VALID_SOURCE)
    assert isinstance(doc, EvidenceDocument)
    assert doc.language == "python"
    assert doc.units == [SourceUnit(path="example.py", language="python")]


def test_syntax_error_handled_safely():
    doc = parse("python", "bad.py", INVALID_SOURCE)
    assert isinstance(doc, EvidenceDocument)
    assert doc.units == [SourceUnit(path="bad.py", language="python")]


def test_empty_evidence_document_returned_for_valid_source():
    doc = parse("python", "example.py", VALID_SOURCE)
    assert doc.facts == []
    assert doc.locations == []


def test_empty_evidence_document_returned_for_syntax_error():
    doc = parse("python", "bad.py", INVALID_SOURCE)
    assert doc.facts == []
    assert doc.locations == []


def test_query_like_code_is_observed_not_classified():
    doc = parse("python", "search.py", SQLI_LOOKING_SOURCE)
    kinds = {fact.kind for fact in doc.facts}
    assert "database_query" in kinds
    assert "issue_type" not in kinds
    data = evidence_to_engine_input(doc)
    assert data["signals"]["injection"]["unsafe_query_construction"] is False
    assert analyze(data).get("vulnerability_indicated") is False
    assert "issue_type" not in data


def test_evidence_model_has_no_classification_fields():
    assert CLASSIFICATION_FIELD_NAMES.isdisjoint(model_field_names())


def test_adapter_returns_empty_engine_structure():
    doc = parse("python", "example.py", VALID_SOURCE)
    data = evidence_to_engine_input(doc)

    assert set(data) == {
        "action",
        "targets",
        "actor",
        "control_point",
        "signals",
        "action_scores",
    }
    assert data["actor"] == "user"
    assert data["signals"] == empty_signals()


def test_adapter_does_not_classify_placeholder_facts():
    doc = empty_document(language="python", path="example.py")
    doc.locations.append(
        Location(id="loc1", path="example.py", line=1),
    )
    doc.facts.append(
        Fact(
            id="f1",
            kind="database_query",
            location_id="loc1",
            attrs={
                "construction": "concat",
                "uses_input_source_ids": [],
                "api": "execute",
                "sql_keywords_present": True,
            },
        )
    )

    data = evidence_to_engine_input(doc)
    assert data["signals"]["injection"]["unsafe_query_construction"] is False
    assert analyze(data).get("vulnerability_indicated") is False
    assert "issue_type" not in data
    assert "findings" not in data
