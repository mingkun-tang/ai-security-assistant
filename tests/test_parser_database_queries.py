"""Python database-query observation. Facts only; no SQL injection classification."""

from app.engine import analyze, empty_signals
from app.parser.adapter import evidence_to_engine_input
from app.parser.python_parser import parse


def parse_queries(source, path="db.py"):
    doc = parse("python", path, source)
    return doc, [fact for fact in doc.facts if fact.kind == "database_query"]


def test_literal_sql():
    source = """
def load():
    cursor.execute("SELECT * FROM users")
"""
    _doc, facts = parse_queries(source)
    assert len(facts) == 1
    assert facts[0].attrs == {
        "api": "execute",
        "construction": "literal",
        "sql_keywords_present": True,
        "uses_input_source_ids": [],
    }


def test_concatenation():
    source = """
def load(username):
    cursor.execute("SELECT * FROM users WHERE name = '" + username)
"""
    _doc, facts = parse_queries(source)
    assert facts[0].attrs["api"] == "execute"
    assert facts[0].attrs["construction"] == "concat"
    assert facts[0].attrs["sql_keywords_present"] is True
    assert facts[0].attrs["uses_input_source_ids"] == []


def test_fstring():
    source = """
def load(username):
    cursor.execute(f"SELECT * FROM users WHERE name = '{username}'")
"""
    _doc, facts = parse_queries(source)
    assert facts[0].attrs["construction"] == "fstring"
    assert facts[0].attrs["sql_keywords_present"] is True


def test_format_method():
    source = """
def load(username):
    cursor.execute("SELECT * FROM users WHERE name = {}".format(username))
"""
    _doc, facts = parse_queries(source)
    assert facts[0].attrs["construction"] == "format"


def test_percent_format():
    source = """
def load(username):
    cursor.execute("SELECT * FROM users WHERE name = '%s'" % username)
"""
    _doc, facts = parse_queries(source)
    assert facts[0].attrs["construction"] == "format"


def test_parameterized_query():
    source = """
def load(user_id):
    cursor.execute(
        "SELECT * FROM users WHERE id=%s",
        (user_id,),
    )
"""
    _doc, facts = parse_queries(source)
    assert facts[0].attrs["api"] == "execute"
    assert facts[0].attrs["construction"] == "parameterized"
    assert facts[0].attrs["sql_keywords_present"] is True
    assert facts[0].attrs["uses_input_source_ids"] == []


def test_executemany():
    source = """
def insert_rows(rows):
    cursor.executemany("INSERT INTO users VALUES (%s)", rows)
"""
    _doc, facts = parse_queries(source)
    assert facts[0].attrs["api"] == "executemany"
    assert facts[0].attrs["construction"] == "parameterized"
    assert facts[0].attrs["sql_keywords_present"] is True


def test_connection_session_and_db_execute():
    source = """
def load():
    connection.execute("SELECT 1")
    session.execute("SELECT 1")
    db.execute("SELECT 1")
"""
    _doc, facts = parse_queries(source)
    assert len(facts) == 3
    assert all(fact.attrs["api"] == "execute" for fact in facts)
    assert all(fact.attrs["construction"] == "literal" for fact in facts)


def test_orm_raw():
    source = """
def load():
    User.objects.raw("SELECT * FROM users")
"""
    _doc, facts = parse_queries(source)
    assert len(facts) == 1
    assert facts[0].attrs["api"] == "raw"
    assert facts[0].attrs["construction"] == "literal"
    assert facts[0].attrs["sql_keywords_present"] is True


def test_sqlalchemy_text_parameterized():
    source = """
def load(user_id):
    session.execute(text("SELECT * FROM users WHERE id = :id"), {"id": user_id})
"""
    _doc, facts = parse_queries(source)
    assert facts[0].attrs["api"] == "execute"
    assert facts[0].attrs["construction"] == "parameterized"
    assert facts[0].attrs["sql_keywords_present"] is True


def test_non_sql_execute_ignored():
    source = """
def worker(pool, executor, job, fn):
    pool.execute(job)
    executor.execute(fn)
    obj.execute("hello world")
"""
    _doc, facts = parse_queries(source)
    assert facts == []


def test_sql_keywords_on_unknown_receiver_still_observed():
    source = """
def load(obj):
    obj.execute("SELECT * FROM users")
"""
    _doc, facts = parse_queries(source)
    assert len(facts) == 1
    assert facts[0].attrs["construction"] == "literal"


def test_location_cites_path_line_and_snippet():
    source = """
def load():
    cursor.execute("SELECT * FROM users")
"""
    doc, facts = parse_queries(source, path="queries.py")
    location = next(loc for loc in doc.locations if loc.id == facts[0].location_id)
    assert location.path == "queries.py"
    assert location.line == 3
    assert isinstance(location.column, int)
    assert "cursor.execute" in (location.snippet or "")


def test_uses_input_source_ids_without_classifying():
    source = """
def view():
    username = request.args.get("name")
    cursor.execute("SELECT * FROM users WHERE name = '" + username)
"""
    doc, facts = parse_queries(source)
    input_ids = [fact.id for fact in doc.facts if fact.kind == "input_source"]
    assert facts[0].attrs["construction"] == "concat"
    assert facts[0].attrs["uses_input_source_ids"] == input_ids
    data = evidence_to_engine_input(doc)
    assert data["signals"]["injection"]["unsafe_query_construction"] is True
    assert analyze(data).get("vulnerability_indicated") is True
    assert "issue_type" not in data


def test_parameterized_input_is_still_not_a_finding():
    source = """
def view():
    user_id = request.args.get("id")
    cursor.execute("SELECT * FROM users WHERE id=%s", (user_id,))
"""
    doc, facts = parse_queries(source)
    assert facts[0].attrs["construction"] == "parameterized"
    assert facts[0].attrs["uses_input_source_ids"]
    result = analyze(evidence_to_engine_input(doc))
    assert result.get("vulnerability_indicated") is False


def test_concat_wins_over_extra_params():
    source = """
def load(username):
    cursor.execute("SELECT * FROM users WHERE name = '" + username, ())
"""
    _doc, facts = parse_queries(source)
    assert facts[0].attrs["construction"] == "concat"


def test_inline_input_call_is_linked_by_id():
    source = """
def view():
    cursor.execute("SELECT * FROM users WHERE name = '" + request.args.get("name"))
"""
    doc, facts = parse_queries(source)
    input_ids = [fact.id for fact in doc.facts if fact.kind == "input_source"]
    assert facts[0].attrs["construction"] == "concat"
    assert facts[0].attrs["uses_input_source_ids"] == input_ids
