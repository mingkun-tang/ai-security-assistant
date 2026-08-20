from app.engine import analyze, normalize_input


def analyze_text(text):
    return analyze(normalize_input(text))


def test_own_profile_is_not_idor():
    result = analyze_text("I can view my own profile")
    assert result["issue_type"] == "unknown"
    assert result["vulnerability_indicated"] is False
    assert result["confidence"] == "high"
    assert result["evidence"]["action"] == "read"
    assert "user data" in result["evidence"]["targets"]


def test_view_another_users_data_is_idor():
    result = analyze_text("I can view another user's data")
    assert result["issue_type"] == "idor"
    assert result["vulnerability_indicated"] is True
    assert result["confidence"] == "high"


def test_change_another_users_email_is_modify_data():
    result = analyze_text("A user can change another user's email")
    assert result["issue_type"] == "modify_data"
    assert result["vulnerability_indicated"] is True
    assert "user email" in result["evidence"]["targets"]
    assert result["impact"] == "possible account takeover"
    assert result["confidence"] == "high"


def test_make_myself_admin_is_privilege_escalation():
    result = analyze_text("I can make myself admin")
    assert result["issue_type"] == "privilege_escalation"
    assert result["vulnerability_indicated"] is True
    assert result["confidence"] == "high"


def test_change_role_is_privilege_escalation():
    result = analyze_text("I can change my role")
    assert result["issue_type"] == "privilege_escalation"
    assert result["vulnerability_indicated"] is True


def test_delete_another_users_account_is_delete_action():
    result = analyze_text("I can delete another user's account")
    assert result["issue_type"] == "delete_action"
    assert result["vulnerability_indicated"] is True
    assert result["confidence"] == "high"


def test_delete_own_account_is_not_delete_action():
    result = analyze_text("I can delete my account")
    assert result["issue_type"] == "unknown"
    assert result["vulnerability_indicated"] is False
    assert result["confidence"] == "high"


def test_garbage_input_is_unknown_with_low_confidence():
    result = analyze_text("asdf qwerty hello world")
    assert result["issue_type"] == "unknown"
    assert result["vulnerability_indicated"] is False
    assert result["confidence"] == "low"


def test_mixed_actions_with_unclear_ownership_are_medium_confidence():
    result = analyze_text("A user can view and change account information")
    assert result["confidence"] == "medium"
    assert result["vulnerability_indicated"] is False
    assert result["issue_type"] == "unknown"


def test_privilege_escalation_wins_when_multiple_vulns_match():
    result = analyze_text(
        "A user can change another user's email and admin role"
    )
    assert result["issue_type"] == "privilege_escalation"
    assert "user email" in result["evidence"]["targets"]
    assert "user role" in result["evidence"]["targets"]


def test_view_another_users_email_is_idor():
    result = analyze_text("I can view another user's email")
    assert result["issue_type"] == "idor"
    assert "user email" in result["evidence"]["targets"]
