from app.engine import analyze, generate_output, normalize_input
from app.knowledge import FOLLOW_UP_QUESTIONS, RECOMMENDATIONS


def analyze_text(text):
    return analyze(normalize_input(text))


def test_csrf_positive_malicious_site_password_change_no_token():
    result = analyze_text(
        "A malicious site can submit a password change while I am logged in "
        "and the request has no CSRF token."
    )
    assert result["issue_type"] == "csrf"
    assert result["vulnerability_indicated"] is True
    assert result["confidence"] == "high"
    assert result["evidence"]["state_change"] is True
    assert result["evidence"]["session_context"] is True
    assert result["evidence"]["cross_site_trigger"] is True
    assert result["evidence"]["missing_anti_csrf_validation"] is True


def test_csrf_positive_another_website_email_change_no_validation():
    result = analyze_text(
        "While the victim is authenticated, another website can trigger an "
        "email change request without request validation."
    )
    assert result["issue_type"] == "csrf"
    assert result["vulnerability_indicated"] is True
    assert result["confidence"] == "high"


def test_csrf_positive_forged_request_deletes_account_with_session_cookie():
    result = analyze_text(
        "The browser automatically sends the session cookie and a forged "
        "request can delete the user's account."
    )
    assert result["issue_type"] == "csrf"
    assert result["vulnerability_indicated"] is True
    assert result["confidence"] == "high"


def test_csrf_negative_normal_profile_update_while_logged_in():
    result = analyze_text("I update my profile while logged in.")
    assert result["issue_type"] != "csrf"
    assert result["vulnerability_indicated"] is False


def test_csrf_negative_session_cookies_only():
    result = analyze_text("The site uses session cookies.")
    assert result["issue_type"] != "csrf"
    assert result["vulnerability_indicated"] is False


def test_csrf_negative_post_requests_only():
    result = analyze_text("The application accepts POST requests.")
    assert result["issue_type"] != "csrf"
    assert result["vulnerability_indicated"] is False


def test_csrf_negative_changed_password_normally():
    result = analyze_text("I changed my password normally.")
    assert result["issue_type"] != "csrf"
    assert result["vulnerability_indicated"] is False


def test_csrf_negative_valid_csrf_token_present():
    result = analyze_text(
        "A malicious site tries to change my password while I am logged in, "
        "but the request includes a valid CSRF token."
    )
    assert result["issue_type"] != "csrf"
    assert result["vulnerability_indicated"] is False


def test_csrf_knowledge_entries_exist():
    assert "csrf" in RECOMMENDATIONS
    assert "csrf" in FOLLOW_UP_QUESTIONS


def test_csrf_cli_report_includes_remediation(capsys):
    text = (
        "A malicious site can submit a password change while I am logged in "
        "and the request has no CSRF token."
    )
    generate_output(text, analyze_text(text))
    output = capsys.readouterr().out
    assert "Possible security issue: Cross-Site Request Forgery (CSRF)" in output
    assert "Use anti-CSRF tokens for state-changing requests where appropriate" in output
    assert "Recommended Remediation" in output


def test_regression_idor_still_works():
    assert analyze_text("I can view another user's data")["issue_type"] == "idor"


def test_regression_modify_data_still_works():
    assert (
        analyze_text("A user can change another user's email")["issue_type"]
        == "modify_data"
    )


def test_regression_privilege_escalation_still_works():
    assert analyze_text("I can make myself admin")["issue_type"] == "privilege_escalation"


def test_regression_sql_injection_still_works():
    assert (
        analyze_text("I can inject SQL into the search parameter.")["issue_type"]
        == "sql_injection"
    )


def test_regression_xss_still_works():
    assert analyze_text("User input is reflected into HTML.")["issue_type"] == "xss"


def test_regression_ssrf_still_works():
    assert (
        analyze_text("The server fetches a URL supplied by the user.")["issue_type"]
        == "ssrf"
    )


def test_regression_file_upload_still_works():
    assert (
        analyze_text("The application lets me upload an executable file.")[
            "issue_type"
        ]
        == "file_upload"
    )
