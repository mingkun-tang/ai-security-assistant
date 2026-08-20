"""Python input-source extraction. Observations only; no classification."""

from app.engine import analyze, empty_signals
from app.parser.adapter import evidence_to_engine_input
from app.parser.python_parser import parse


def parse_facts(source, path="app.py"):
    doc = parse("python", path, source)
    return doc, [fact for fact in doc.facts if fact.kind == "input_source"]


def test_flask_request_args_subscript():
    source = """
def view():
    value = request.args["id"]
"""
    _doc, facts = parse_facts(source)
    assert len(facts) == 1
    assert facts[0].attrs == {
        "channel": "query",
        "name": "id",
        "user_controlled": True,
        "framework": "flask",
        "bound_name": "value",
    }


def test_flask_request_args_get():
    source = """
def view():
    user_id = request.args.get("id")
"""
    _doc, facts = parse_facts(source)
    assert len(facts) == 1
    assert facts[0].attrs["channel"] == "query"
    assert facts[0].attrs["name"] == "id"
    assert facts[0].attrs["framework"] == "flask"
    assert facts[0].attrs["user_controlled"] is True
    assert facts[0].attrs["bound_name"] == "user_id"


def test_flask_request_form():
    source = """
def view():
    request.form["email"]
    request.form.get("email")
"""
    _doc, facts = parse_facts(source)
    assert [fact.attrs["channel"] for fact in facts] == ["form", "form"]
    assert [fact.attrs["name"] for fact in facts] == ["email", "email"]
    assert all(fact.attrs["framework"] == "flask" for fact in facts)


def test_flask_json_body():
    source = """
def view():
    payload = request.json
    request.get_json()
"""
    _doc, facts = parse_facts(source)
    assert len(facts) == 2
    assert facts[0].attrs["channel"] == "json_body"
    assert facts[0].attrs["name"] is None
    assert facts[0].attrs["bound_name"] == "payload"
    assert facts[0].attrs["framework"] == "flask"
    assert facts[1].attrs["channel"] == "json_body"
    assert facts[1].attrs["name"] is None


def test_flask_headers_and_cookies():
    source = """
def view():
    request.headers["X-Request-Id"]
    request.headers.get("X-Token")
    request.cookies.get("session")
"""
    _doc, facts = parse_facts(source)
    assert [fact.attrs["channel"] for fact in facts] == ["header", "header", "cookie"]
    assert [fact.attrs["name"] for fact in facts] == [
        "X-Request-Id",
        "X-Token",
        "session",
    ]
    assert all(fact.attrs["framework"] == "flask" for fact in facts)


def test_django_get_post_body():
    source = """
def view(request):
    request.GET["id"]
    request.GET.get("id")
    request.POST["email"]
    request.POST.get("email")
    raw = request.body
"""
    _doc, facts = parse_facts(source)
    assert [fact.attrs["channel"] for fact in facts] == [
        "query",
        "query",
        "form",
        "form",
        "raw_body",
    ]
    assert [fact.attrs["name"] for fact in facts] == ["id", "id", "email", "email", None]
    assert [fact.attrs["framework"] for fact in facts] == [
        "django",
        "django",
        "django",
        "django",
        "django",
    ]
    assert facts[-1].attrs["bound_name"] == "raw"


def test_generic_input_argv_and_environment():
    source = """
def main():
    value = input()
    args = sys.argv
    os.environ.get("API_KEY")
    os.getenv("HOME")
"""
    _doc, facts = parse_facts(source)
    assert [fact.attrs["channel"] for fact in facts] == [
        "stdin",
        "argv",
        "environment",
        "environment",
    ]
    assert [fact.attrs["name"] for fact in facts] == [None, None, "API_KEY", "HOME"]
    assert [fact.attrs["framework"] for fact in facts] == [None, None, None, None]
    assert facts[0].attrs["bound_name"] == "value"
    assert facts[1].attrs["bound_name"] == "args"


def test_os_environ_subscript():
    source = """
def main():
    os.environ["TOKEN"]
"""
    _doc, facts = parse_facts(source)
    assert facts[0].attrs["channel"] == "environment"
    assert facts[0].attrs["name"] == "TOKEN"


def test_unknown_parameter_name_is_none():
    source = """
def view():
    key = "id"
    request.args.get(key)
    request.args[key]
"""
    _doc, facts = parse_facts(source)
    assert len(facts) == 2
    assert facts[0].attrs["name"] is None
    assert facts[1].attrs["name"] is None


def test_location_cites_path_line_and_snippet():
    source = """
def view():
    request.args.get("id")
"""
    doc, facts = parse_facts(source, path="views.py")
    assert len(facts) == 1
    location = next(loc for loc in doc.locations if loc.id == facts[0].location_id)
    assert location.path == "views.py"
    assert location.line == 3
    assert isinstance(location.column, int)
    assert "request.args.get" in (location.snippet or "")


def test_json_subscript_uses_key_name():
    source = """
def view():
    request.json["email"]
"""
    _doc, facts = parse_facts(source)
    assert len(facts) == 1
    assert facts[0].attrs["channel"] == "json_body"
    assert facts[0].attrs["name"] == "email"
    assert facts[0].attrs["framework"] == "flask"


def test_local_alias_of_input_source():
    source = """
def view():
    user_id = request.args.get("id")
"""
    _doc, facts = parse_facts(source)
    assert facts[0].attrs["bound_name"] == "user_id"
    assert facts[0].kind == "input_source"


def test_local_alias_of_request_container():
    source = """
def view():
    args = request.args
    user_id = args.get("id")
    other = args["q"]
"""
    _doc, facts = parse_facts(source)
    assert len(facts) == 2
    assert facts[0].attrs["name"] == "id"
    assert facts[0].attrs["channel"] == "query"
    assert facts[0].attrs["framework"] == "flask"
    assert facts[0].attrs["bound_name"] == "user_id"
    assert facts[1].attrs["name"] == "q"
    assert facts[1].attrs["bound_name"] == "other"


def test_aliases_do_not_cross_functions():
    source = """
def one():
    args = request.args

def two():
    args.get("id")
"""
    _doc, facts = parse_facts(source)
    assert facts == []


def test_unrelated_get_is_not_an_input_source():
    source = """
def view(config):
    config.get("id")
    values["id"]
"""
    _doc, facts = parse_facts(source)
    assert facts == []


def test_self_request_django_get():
    source = """
class View:
    def get(self):
        self.request.GET.get("id")
"""
    _doc, facts = parse_facts(source)
    assert len(facts) == 1
    assert facts[0].attrs["framework"] == "django"
    assert facts[0].attrs["channel"] == "query"
    assert facts[0].attrs["name"] == "id"


def test_input_source_is_not_classified_as_a_finding():
    source = """
def view():
    name = request.args.get("name")
    value = input()
"""
    doc, facts = parse_facts(source)
    assert {fact.kind for fact in facts} == {"input_source"}
    assert all(fact.kind != "vulnerability" for fact in doc.facts)
    data = evidence_to_engine_input(doc)
    assert data["signals"]["input"]["user_controlled_input"] is True
    assert analyze(data).get("vulnerability_indicated") is False
    assert "issue_type" not in data
    assert "findings" not in data
    assert "vulnerability_indicated" not in data


def test_query_without_request_input_has_no_input_source_facts():
    source = """
def search(q):
    cursor.execute("SELECT * FROM users WHERE name = '%s'" % q)
"""
    _doc, facts = parse_facts(source)
    assert facts == []
