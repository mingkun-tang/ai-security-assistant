from app.engine import normalize_input, term_in_text


def test_other_user_and_self_reference_signals():
    own_profile = normalize_input("I can view my own profile")
    other_profile = normalize_input("I can view another user's profile")

    assert own_profile["signals"]["ownership"]["self_reference"] is True
    assert own_profile["signals"]["ownership"]["other_user"] is False
    assert other_profile["signals"]["ownership"]["other_user"] is True
    assert other_profile["signals"]["ownership"]["self_reference"] is False


def test_authorization_data_and_authentication_signals_are_filled():
    data = normalize_input(
        "A user can change a permission and login with a password to read sensitive data"
    )
    signals = data["signals"]

    assert signals["authorization"]["permission_reference"] is True
    assert signals["authorization"]["role_change"] is False
    assert signals["data"]["sensitive_data_reference"] is True
    assert signals["authentication"]["login_reference"] is True
    assert signals["authentication"]["password_reference"] is True


def test_role_change_signal_when_role_and_modify_words_appear():
    data = normalize_input("I can change my role")
    assert data["signals"]["authorization"]["role_change"] is True
    assert data["signals"]["authorization"]["admin_reference"] is False


def test_admin_reference_signal():
    data = normalize_input("I can make myself admin")
    assert data["signals"]["authorization"]["admin_reference"] is True
    assert data["signals"]["ownership"]["self_reference"] is True


def test_email_is_not_overwritten_by_later_targets():
    data = normalize_input("A user can change another user's email")
    assert "user email" in data["targets"]
    assert data["action"] == "modify"
    assert data["signals"]["ownership"]["other_user"] is True


def test_multiple_targets_can_coexist():
    data = normalize_input(
        "A user can change another user's email and admin role"
    )
    assert "user email" in data["targets"]
    assert "user role" in data["targets"]


def test_word_boundary_does_not_treat_already_as_read():
    data = normalize_input("The token was already issued")
    assert data["action"] is None
    assert data["action_scores"]["read"] == 0


def test_word_boundary_does_not_treat_unchecked_as_check():
    data = normalize_input("The box was left unchecked")
    assert data["action"] is None
    assert data["action_scores"]["read"] == 0


def test_term_in_text_matches_another_user_inside_possessive():
    assert term_in_text("another user's email", "another user") is True
