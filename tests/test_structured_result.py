from app.engine import analyze, analyze_scenario, build_structured_result, normalize_input


def structured(text):
    return analyze_scenario(text)


def test_structured_result_one_finding():
    report = structured("I can view another user's data")

    assert report["scenario"] == "I can view another user's data"
    assert report["vulnerability_indicated"] is True
    assert report["primary_issue"] == "idor"
    assert len(report["findings"]) == 1

    finding = report["findings"][0]
    assert finding["issue_type"] == "idor"
    assert finding["display_name"] == "Insecure Direct Object Reference (IDOR)"
    assert finding["confidence"] == "high"
    assert finding["evidence"]["action"] == "read"
    assert finding["evidence"]["other_user"] is True
    assert "authorization" in finding["missing_control"].lower()
    assert finding["recommendations"]
    assert finding["follow_up_questions"]


def test_structured_result_multiple_findings():
    report = structured(
        "The search parameter is concatenated into a SQL query and user input "
        "is reflected into HTML."
    )

    assert report["vulnerability_indicated"] is True
    assert report["primary_issue"] == "sql_injection"
    assert [finding["issue_type"] for finding in report["findings"]] == [
        "sql_injection",
        "xss",
    ]
    assert report["findings"][0]["display_name"] == "SQL Injection"
    assert report["findings"][1]["display_name"] == "Cross-Site Scripting (XSS)"
    assert all(finding["confidence"] == "high" for finding in report["findings"])


def test_structured_result_no_finding():
    report = structured("I can view my own profile")

    assert report["scenario"] == "I can view my own profile"
    assert report["findings"] == []
    assert report["primary_issue"] is None
    assert report["vulnerability_indicated"] is False
    assert report["summary"]["verification_steps"]


def test_structured_result_preserves_evidence_per_finding():
    report = structured(
        "The server fetches a URL supplied by the user and the application "
        "lets me upload an executable file."
    )

    assert len(report["findings"]) == 2
    for finding in report["findings"]:
        assert finding["evidence"]["server_request"] is True
        assert finding["evidence"]["user_controlled_url"] is True
        assert finding["evidence"]["file_upload_action"] is True
        assert finding["evidence"]["dangerous_file"] is True


def test_structured_result_preserves_recommendations_and_follow_ups():
    report = structured("I can inject SQL into the search parameter.")
    finding = report["findings"][0]

    assert finding["issue_type"] == "sql_injection"
    assert "Use parameterized or prepared statements for all database access" in (
        finding["recommendations"]
    )
    assert "Is the value concatenated into a SQL string?" in (
        finding["follow_up_questions"]
    )


def test_build_structured_result_matches_analyze_scenario():
    text = "A user can change another user's email"
    analysis = analyze(normalize_input(text))
    from_builder = build_structured_result(text, analysis)
    from_helper = analyze_scenario(text)

    assert from_builder == from_helper
    assert from_builder["primary_issue"] == "modify_data"
    assert from_builder["findings"][0]["issue_type"] == "modify_data"
