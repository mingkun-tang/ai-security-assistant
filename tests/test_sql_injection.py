from engine import analyze, generate_output, normalize_input
from knowledge import FOLLOW_UP_QUESTIONS, RECOMMENDATIONS


def analyze_text(text):
    return analyze(normalize_input(text))


def test_sql_injection_positive_inject_into_search_parameter():
    result = analyze_text("I can inject SQL into the search parameter.")
    assert result["issue_type"] == "sql_injection"
    assert result["vulnerability_indicated"] is True
    assert result["confidence"] == "high"
    assert "database" in result["evidence"]["targets"]
    assert result["evidence"]["user_controlled_input"] is True
    assert result["evidence"]["database_context"] is True
    assert result["evidence"]["injection_attempt"] is True


def test_sql_injection_positive_unsanitized_query_parameter():
    result = analyze_text(
        "The search parameter is concatenated into a SQL query without validation."
    )
    assert result["issue_type"] == "sql_injection"
    assert result["vulnerability_indicated"] is True
    assert result["confidence"] == "high"


def test_sql_injection_negative_profile_stored_in_sql():
    result = analyze_text("My profile is stored in SQL.")
    assert result["issue_type"] != "sql_injection"
    assert result["vulnerability_indicated"] is False


def test_sql_injection_negative_mentions_database_only():
    result = analyze_text("The application uses a SQL database.")
    assert result["issue_type"] != "sql_injection"
    assert result["vulnerability_indicated"] is False


def test_sql_injection_signals_are_collected_for_positive_case():
    data = normalize_input("I can inject SQL into the search parameter.")
    assert data["signals"]["input"]["user_controlled_input"] is True
    assert data["signals"]["input"]["parameter_reference"] is True
    assert data["signals"]["injection"]["database_context"] is True
    assert data["signals"]["injection"]["injection_attempt"] is True
    assert "database" in data["targets"]
    assert data["action"] == "inject"


def test_sql_injection_knowledge_entries_exist():
    assert "sql_injection" in RECOMMENDATIONS
    assert "sql_injection" in FOLLOW_UP_QUESTIONS


def test_sql_injection_cli_report_includes_remediation(capsys):
    text = "I can inject SQL into the search parameter."
    generate_output(text, analyze_text(text))
    output = capsys.readouterr().out
    assert "Possible security issue: SQL Injection" in output
    assert "Use parameterized queries or a safe ORM for all database access" in output
    assert "Recommended Remediation" in output
