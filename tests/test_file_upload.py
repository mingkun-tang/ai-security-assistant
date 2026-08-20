from app.engine import analyze, generate_output, normalize_input
from app.knowledge import FOLLOW_UP_QUESTIONS, RECOMMENDATIONS


def analyze_text(text):
    return analyze(normalize_input(text))


def test_file_upload_positive_php_served_from_uploads():
    result = analyze_text(
        "I can upload a PHP file and the server serves it from the uploads folder."
    )
    assert result["issue_type"] == "file_upload"
    assert result["vulnerability_indicated"] is True
    assert result["confidence"] == "high"
    assert result["evidence"]["file_upload_action"] is True
    assert result["evidence"]["dangerous_file"] is True
    assert result["evidence"]["execution_context"] is True


def test_file_upload_positive_executable_file():
    result = analyze_text("The application lets me upload an executable file.")
    assert result["issue_type"] == "file_upload"
    assert result["vulnerability_indicated"] is True
    assert result["confidence"] == "high"


def test_file_upload_positive_script_accessible_from_website():
    result = analyze_text(
        "I can upload a script file and access it from the website."
    )
    assert result["issue_type"] == "file_upload"
    assert result["vulnerability_indicated"] is True
    assert result["confidence"] == "high"


def test_file_upload_negative_jpg_profile_picture():
    result = analyze_text("I uploaded a JPG profile picture.")
    assert result["issue_type"] != "file_upload"
    assert result["vulnerability_indicated"] is False


def test_file_upload_negative_pdf_uploads():
    result = analyze_text("The application allows PDF uploads.")
    assert result["issue_type"] != "file_upload"
    assert result["vulnerability_indicated"] is False


def test_file_upload_negative_upload_button_only():
    result = analyze_text("There is an upload button.")
    assert result["issue_type"] != "file_upload"
    assert result["vulnerability_indicated"] is False


def test_file_upload_negative_selected_file_only():
    result = analyze_text("I selected a file from my computer.")
    assert result["issue_type"] != "file_upload"
    assert result["vulnerability_indicated"] is False


def test_file_upload_does_not_fire_on_php_mention_alone():
    result = analyze_text("The server runs PHP applications.")
    assert result["issue_type"] != "file_upload"
    assert result["vulnerability_indicated"] is False


def test_file_upload_knowledge_entries_exist():
    assert "file_upload" in RECOMMENDATIONS
    assert "file_upload" in FOLLOW_UP_QUESTIONS


def test_file_upload_cli_report_includes_remediation(capsys):
    text = "The application lets me upload an executable file."
    generate_output(text, analyze_text(text))
    output = capsys.readouterr().out
    assert "Possible security issue: Insecure File Upload" in output
    assert "Allowlist approved file types rather than blocking a denylist" in output
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
