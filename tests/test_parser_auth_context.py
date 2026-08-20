"""Python auth_context observation. Facts only; no auth/CSRF/IDOR classification."""

from app.engine import analyze, empty_signals
from app.parser.adapter import evidence_to_engine_input
from app.parser.python_parser import parse


def parse_auth(source, path="auth.py"):
    doc = parse("python", path, source)
    return doc, [fact for fact in doc.facts if fact.kind == "auth_context"]


def test_flask_session_subscript():
    source = """
def view():
    session["user_id"]
"""
    _doc, facts = parse_auth(source)
    assert len(facts) == 1
    assert facts[0].attrs["auth_kind"] == "session"
    assert facts[0].attrs["framework"] == "flask"
    assert facts[0].attrs["ambient_credentials"] == "yes"
    assert facts[0].attrs["source_name"] == "user_id"


def test_flask_session_get():
    source = """
def view():
    session.get("user_id")
"""
    _doc, facts = parse_auth(source)
    assert facts[0].attrs["auth_kind"] == "session"
    assert facts[0].attrs["framework"] == "flask"


def test_flask_current_user():
    source = """
def view():
    user = current_user
"""
    _doc, facts = parse_auth(source)
    assert facts[0].attrs["auth_kind"] == "current_user"
    assert facts[0].attrs["authenticated_context"] == "yes"
    assert facts[0].attrs["framework"] == "flask"


def test_flask_login_required():
    source = """
@login_required
def dashboard():
    return True
"""
    _doc, facts = parse_auth(source)
    assert len(facts) == 1
    assert facts[0].attrs["auth_kind"] == "login_guard"
    assert facts[0].attrs["authenticated_context"] == "yes"
    assert facts[0].attrs["guard_observed"] == "yes"


def test_django_request_user():
    source = """
def view(request):
    return request.user
"""
    _doc, facts = parse_auth(source)
    assert facts[0].attrs["auth_kind"] == "request_user"
    assert facts[0].attrs["framework"] == "django"
    assert facts[0].attrs["authenticated_context"] == "yes"


def test_django_request_session():
    source = """
def view(request):
    request.session["user_id"]
"""
    _doc, facts = parse_auth(source)
    assert facts[0].attrs["auth_kind"] == "session"
    assert facts[0].attrs["framework"] == "django"
    assert facts[0].attrs["ambient_credentials"] == "yes"


def test_authorization_header():
    source = """
def view():
    token = request.headers.get("Authorization")
"""
    _doc, facts = parse_auth(source)
    assert facts[0].attrs["auth_kind"] == "authorization_header"
    assert facts[0].attrs["authenticated_context"] == "unknown"
    assert facts[0].attrs["ambient_credentials"] == "no"
    assert facts[0].attrs["source_name"] == "Authorization"


def test_jwt_decode_with_validation():
    source = """
def view(token, key):
    jwt.decode(token, key, algorithms=["HS256"])
"""
    _doc, facts = parse_auth(source)
    assert facts[0].attrs["auth_kind"] == "jwt"
    assert facts[0].attrs["authenticated_context"] == "yes"
    assert facts[0].attrs["guard_observed"] == "yes"


def test_jwt_decode_without_key_is_unknown():
    source = """
def view(token):
    jwt.decode(token)
"""
    _doc, facts = parse_auth(source)
    assert facts[0].attrs["auth_kind"] == "jwt"
    assert facts[0].attrs["authenticated_context"] == "unknown"


def test_unrelated_session_variable_ignored():
    source = """
def view():
    session = {}
    session["user_id"] = 1
"""
    _doc, facts = parse_auth(source)
    assert facts == []


def test_location_cites_path_line_and_snippet():
    source = """
def view():
    session["user_id"]
"""
    doc, facts = parse_auth(source, path="views.py")
    location = next(loc for loc in doc.locations if loc.id == facts[0].location_id)
    assert location.path == "views.py"
    assert location.line == 3
    assert isinstance(location.column, int)
    assert "session" in (location.snippet or "")


def test_auth_context_is_not_classified():
    source = """
@login_required
def view():
    session["user_id"]
    jwt.decode(token, key, algorithms=["HS256"])
"""
    doc, facts = parse_auth(source)
    assert {fact.kind for fact in facts} <= {"auth_context"}
    data = evidence_to_engine_input(doc)
    assert analyze(data).get("vulnerability_indicated") is False
    assert "issue_type" not in data
