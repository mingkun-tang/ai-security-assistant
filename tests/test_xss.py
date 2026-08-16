from engine import analyze, generate_output, normalize_input
from knowledge import FOLLOW_UP_QUESTIONS, RECOMMENDATIONS


def analyze_text(text):
    return analyze(normalize_input(text))


def test_xss_positive_inject_javascript_into_comment_field():
    result = analyze_text("I can inject JavaScript into the comment field.")
    assert result["issue_type"] == "xss"
    assert result["vulnerability_indicated"] is True
    assert result["confidence"] == "high"
    assert result["evidence"]["user_controlled_input"] is True
    assert result["evidence"]["javascript_context"] is True
    assert result["evidence"]["injection_attempt"] is True


def test_xss_positive_user_input_reflected_into_html():
    result = analyze_text("User input is reflected into HTML.")
    assert result["issue_type"] == "xss"
    assert result["vulnerability_indicated"] is True
    assert result["confidence"] == "high"
    assert result["evidence"]["user_controlled_input"] is True
    assert result["evidence"]["html_context"] is True
    assert result["evidence"]["reflected_output"] is True


def test_xss_positive_input_appears_inside_html():
    result = analyze_text("My input appears inside HTML.")
    assert result["issue_type"] == "xss"
    assert result["vulnerability_indicated"] is True


def test_xss_negative_page_uses_javascript():
    result = analyze_text("The page uses JavaScript.")
    assert result["issue_type"] != "xss"
    assert result["vulnerability_indicated"] is False


def test_xss_negative_learning_html():
    result = analyze_text("I am learning HTML.")
    assert result["issue_type"] != "xss"
    assert result["vulnerability_indicated"] is False


def test_xss_negative_website_uses_javascript():
    result = analyze_text("The website uses JavaScript.")
    assert result["issue_type"] != "xss"
    assert result["vulnerability_indicated"] is False


def test_xss_does_not_steal_sql_injection_case():
    result = analyze_text("I can inject SQL into the search parameter.")
    assert result["issue_type"] == "sql_injection"
    assert result["issue_type"] != "xss"


def test_xss_knowledge_entries_exist():
    assert "xss" in RECOMMENDATIONS
    assert "xss" in FOLLOW_UP_QUESTIONS


def test_xss_cli_report_includes_remediation(capsys):
    text = "User input is reflected into HTML."
    generate_output(text, analyze_text(text))
    output = capsys.readouterr().out
    assert "Possible security issue: Cross-Site Scripting (XSS)" in output
    assert "Apply context-aware output encoding before rendering user input" in output
    assert "Recommended Remediation" in output
