from app.engine import analyze, generate_output, normalize_input
from app.knowledge import FOLLOW_UP_QUESTIONS


def run_output(capsys, text):
    analysis = analyze(normalize_input(text))
    generate_output(text, analysis)
    return capsys.readouterr().out, analysis


def test_output_does_not_dump_raw_normalize_dict(capsys):
    output, _ = run_output(capsys, "I can view my own profile")
    assert "action_scores" not in output
    assert "{'action'" not in output
    assert '"action"' not in output


def test_own_profile_output_teaches_no_clear_issue(capsys):
    output, analysis = run_output(capsys, "I can view my own profile")
    assert analysis["vulnerability_indicated"] is False
    assert "No evidence of unauthorized access detected." in output
    assert "Evidence Collected" in output
    assert "Other User Referenced:  No" in output
    assert "Ownership:              Self" in output
    assert "Follow-up questions:" not in output


def test_idor_output_includes_recommendations(capsys):
    output, analysis = run_output(capsys, "I can view another user's data")
    assert analysis["issue_type"] == "idor"
    assert "Possible security issue" in output
    assert "Enforce object-level authorization checks" in output


def test_privilege_escalation_follow_up_key_is_correct():
    assert "privilege_escalation" in FOLLOW_UP_QUESTIONS
    assert "priviledge_escalation" not in FOLLOW_UP_QUESTIONS


def test_medium_confidence_privilege_escalation_prints_follow_ups(capsys):
    output, analysis = run_output(
        capsys,
        "I can change my role and another user's role",
    )
    assert analysis["issue_type"] == "privilege_escalation"
    assert analysis["confidence"] == "medium"
    assert "Follow-up questions:" in output
    assert "Can a normal user assign themselves higher privileges?" in output


def test_low_confidence_unknown_prints_follow_ups(capsys):
    output, analysis = run_output(capsys, "something vague happened")
    assert analysis["confidence"] == "low"
    assert "Follow-up questions:" in output
    assert "What action is being performed?" in output
