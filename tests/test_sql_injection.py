from engine import analyze, generate_output, normalize_input
from knowledge import FOLLOW_UP_QUESTIONS, RECOMMENDATIONS


def analyze_text(text):
    return analyze(normalize_input(text))


def test_sql_injection_positive_search_parameter_concatenated():
    result = analyze_text(
        "The search parameter is concatenated into a SQL query."
    )
    assert result["issue_type"] == "sql_injection"
    assert result["vulnerability_indicated"] is True
    assert result["confidence"] == "high"


def test_sql_injection_positive_username_inserted_into_where():
    result = analyze_text(
        "The username is inserted directly into the WHERE clause."
    )
    assert result["issue_type"] == "sql_injection"
    assert result["vulnerability_indicated"] is True
    assert result["confidence"] == "high"


def test_sql_injection_positive_builds_sql_with_concatenation_from_user_input():
    result = analyze_text(
        "The application builds SQL with string concatenation from user input."
    )
    assert result["issue_type"] == "sql_injection"
    assert result["vulnerability_indicated"] is True
    assert result["confidence"] == "high"


def test_sql_injection_positive_request_parameter_into_select():
    result = analyze_text(
        "The request parameter is concatenated into a SELECT statement."
    )
    assert result["issue_type"] == "sql_injection"
    assert result["vulnerability_indicated"] is True
    assert result["confidence"] == "high"


def test_sql_injection_positive_login_query_string_concatenation():
    result = analyze_text(
        "A login query is built with string concatenation from username and password."
    )
    assert result["issue_type"] == "sql_injection"
    assert result["vulnerability_indicated"] is True
    assert result["confidence"] == "high"


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


def test_sql_injection_negative_uses_postgresql():
    result = analyze_text("My application uses PostgreSQL.")
    assert result["issue_type"] != "sql_injection"
    assert result["vulnerability_indicated"] is False


def test_sql_injection_negative_stores_users_in_sql():
    result = analyze_text("The application stores users in SQL.")
    assert result["issue_type"] != "sql_injection"
    assert result["vulnerability_indicated"] is False


def test_sql_injection_negative_select_query_retrieves_data():
    result = analyze_text("A SELECT query retrieves data.")
    assert result["issue_type"] != "sql_injection"
    assert result["vulnerability_indicated"] is False


def test_sql_injection_negative_database_contains_accounts():
    result = analyze_text("The database contains user accounts.")
    assert result["issue_type"] != "sql_injection"
    assert result["vulnerability_indicated"] is False


def test_sql_injection_negative_mentions_database_only():
    result = analyze_text("The application uses a SQL database.")
    assert result["issue_type"] != "sql_injection"
    assert result["vulnerability_indicated"] is False


def test_sql_injection_negative_parameterized_query_present():
    result = analyze_text(
        "The search parameter is passed to a parameterized query."
    )
    assert result["issue_type"] != "sql_injection"
    assert result["vulnerability_indicated"] is False


def test_sql_injection_partial_evidence_is_medium_not_finding():
    result = analyze_text(
        "The search parameter is used with the SQL database."
    )
    assert result["issue_type"] != "sql_injection"
    assert result["vulnerability_indicated"] is False
    assert result["confidence"] == "medium"


def test_sql_injection_signals_are_collected_for_positive_case():
    data = normalize_input("I can inject SQL into the search parameter.")
    assert data["signals"]["input"]["user_controlled_input"] is True
    assert data["signals"]["input"]["parameter_reference"] is True
    assert data["signals"]["injection"]["database_context"] is True
    assert data["signals"]["injection"]["injection_attempt"] is True
    assert data["signals"]["query_construction"]["unsafe_construction"] is False
    assert "database" in data["targets"]
    assert data["action"] == "inject"


def test_sql_injection_knowledge_entries_exist():
    assert "sql_injection" in RECOMMENDATIONS
    assert "sql_injection" in FOLLOW_UP_QUESTIONS


def test_sql_injection_cli_report_includes_remediation(capsys):
    text = "The search parameter is concatenated into a SQL query."
    generate_output(text, analyze_text(text))
    output = capsys.readouterr().out
    assert "Possible security issue: SQL Injection" in output
    assert "Use parameterized or prepared statements for all database access" in output
    assert "Recommended Remediation" in output
