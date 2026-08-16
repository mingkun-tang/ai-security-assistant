from engine import analyze, generate_output, normalize_input
from knowledge import FOLLOW_UP_QUESTIONS, RECOMMENDATIONS


def analyze_text(text):
    return analyze(normalize_input(text))


def test_ssrf_positive_server_fetches_user_supplied_url():
    result = analyze_text("The server fetches a URL supplied by the user.")
    assert result["issue_type"] == "ssrf"
    assert result["vulnerability_indicated"] is True
    assert result["confidence"] == "high"
    assert result["evidence"]["server_request"] is True
    assert result["evidence"]["user_controlled_url"] is True
    assert result["evidence"]["destination_reference"] is True
    assert "remote url" in result["evidence"]["targets"]


def test_ssrf_positive_change_url_parameter_backend_request():
    result = analyze_text(
        "I can change the URL parameter and make the backend request another host."
    )
    assert result["issue_type"] == "ssrf"
    assert result["vulnerability_indicated"] is True
    assert result["confidence"] == "high"


def test_ssrf_positive_callback_url_server_connects():
    result = analyze_text(
        "The application server connects to whatever callback URL I provide."
    )
    assert result["issue_type"] == "ssrf"
    assert result["vulnerability_indicated"] is True
    assert result["confidence"] == "high"


def test_ssrf_negative_browser_opens_website():
    result = analyze_text("My browser opens another website.")
    assert result["issue_type"] != "ssrf"
    assert result["vulnerability_indicated"] is False


def test_ssrf_negative_page_contains_link():
    result = analyze_text("The page contains a link to another domain.")
    assert result["issue_type"] != "ssrf"
    assert result["vulnerability_indicated"] is False


def test_ssrf_negative_external_api_only():
    result = analyze_text("The application uses an external API.")
    assert result["issue_type"] != "ssrf"
    assert result["vulnerability_indicated"] is False


def test_ssrf_negative_url_entered_in_form_without_server_fetch():
    result = analyze_text("I entered a URL into a form.")
    assert result["issue_type"] != "ssrf"
    assert result["vulnerability_indicated"] is False


def test_ssrf_signals_require_server_and_user_destination():
    data = normalize_input("The server fetches a URL supplied by the user.")
    assert data["signals"]["network"]["server_request"] is True
    assert data["signals"]["network"]["user_controlled_url"] is True
    assert data["signals"]["network"]["destination_reference"] is True


def test_ssrf_knowledge_entries_exist():
    assert "ssrf" in RECOMMENDATIONS
    assert "ssrf" in FOLLOW_UP_QUESTIONS


def test_ssrf_cli_report_includes_remediation(capsys):
    text = "The server fetches a URL supplied by the user."
    generate_output(text, analyze_text(text))
    output = capsys.readouterr().out
    assert "Possible security issue: Server-Side Request Forgery (SSRF)" in output
    assert "Allowlist approved destinations where practical" in output
    assert "Recommended Remediation" in output


def test_regression_idor_still_works():
    result = analyze_text("I can view another user's data")
    assert result["issue_type"] == "idor"
    assert result["vulnerability_indicated"] is True


def test_regression_modify_data_still_works():
    result = analyze_text("A user can change another user's email")
    assert result["issue_type"] == "modify_data"
    assert result["vulnerability_indicated"] is True


def test_regression_privilege_escalation_still_works():
    result = analyze_text("I can make myself admin")
    assert result["issue_type"] == "privilege_escalation"
    assert result["vulnerability_indicated"] is True


def test_regression_sql_injection_still_works():
    result = analyze_text("I can inject SQL into the search parameter.")
    assert result["issue_type"] == "sql_injection"
    assert result["vulnerability_indicated"] is True


def test_regression_xss_still_works():
    result = analyze_text("User input is reflected into HTML.")
    assert result["issue_type"] == "xss"
    assert result["vulnerability_indicated"] is True
