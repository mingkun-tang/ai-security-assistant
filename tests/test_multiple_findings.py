from engine import analyze, generate_output, normalize_input


def analyze_text(text):
    return analyze(normalize_input(text))


def finding_types(result):
    return [finding["issue_type"] for finding in result["findings"]]


def test_single_issue_exposes_one_finding_and_keeps_primary_fields():
    result = analyze_text("I can view another user's data")

    assert result["issue_type"] == "idor"
    assert result["primary_issue"] == "idor"
    assert finding_types(result) == ["idor"]
    assert result["findings"][0]["confidence"] == result["confidence"] == "high"


def test_no_issue_exposes_an_empty_findings_list():
    result = analyze_text("I can view my own profile")

    assert result["issue_type"] == "unknown"
    assert result["primary_issue"] == "unknown"
    assert result["findings"] == []
    assert result["vulnerability_indicated"] is False


def test_sqli_and_xss_are_reported_as_independent_findings():
    result = analyze_text(
        "The search parameter is concatenated into a SQL query and user input "
        "is reflected into HTML."
    )

    assert finding_types(result) == ["sql_injection", "xss"]
    assert result["issue_type"] == "sql_injection"
    assert result["primary_issue"] == "sql_injection"
    assert all(finding["confidence"] == "high" for finding in result["findings"])


def test_ssrf_and_file_upload_are_reported_as_independent_findings():
    result = analyze_text(
        "The server fetches a URL supplied by the user and the application "
        "lets me upload an executable file."
    )

    assert finding_types(result) == ["ssrf", "file_upload"]
    assert result["issue_type"] == "ssrf"
    assert result["primary_issue"] == "ssrf"
    assert all(finding["confidence"] == "high" for finding in result["findings"])


def test_multiple_findings_cli_report_shows_index_and_details(capsys):
    text = (
        "The search parameter is concatenated into a SQL query and user input "
        "is reflected into HTML."
    )
    generate_output(text, analyze_text(text))
    output = capsys.readouterr().out

    assert "Findings" in output
    assert "1. SQL Injection — High" in output
    assert "2. Cross-Site Scripting (XSS) — High" in output
    assert "Finding 1 — SQL Injection" in output
    assert "Finding 2 — Cross-Site Scripting (XSS)" in output
    assert output.count("Recommended remediation:") == 2
