"""Final targeted architecture sprint — generalized mechanisms (not Holdout #3)."""

from app.engine import analyze
from app.parser.adapter import evidence_to_engine_input
from app.parser.python_parser import parse


def _analyze(source: str) -> dict:
    doc = parse("python", "sample.py", source)
    data = evidence_to_engine_input(doc)
    analysis = analyze(data)
    return {
        "primary_issue": analysis.get("issue_type"),
        "findings": analysis.get("findings") or [],
        "doc": doc,
    }


def _has_issue(result: dict, issue: str) -> bool:
    if result["primary_issue"] == issue:
        return True
    return any(f.get("issue_type") == issue for f in result["findings"])


def test_sqlalchemy_text_format_bound_then_execute():
    source = """
def fetch(session):
    key = request.args.get("key")
    stmt = text("SELECT * FROM items WHERE code = '{}'".format(key))
    return session.execute(stmt)
"""
    assert _analyze(source)["primary_issue"] == "sql_injection"


def test_sqlalchemy_text_fstring_inline_execute():
    source = """
def fetch(session):
    key = request.args.get("key")
    return session.execute(text(f"SELECT * FROM items WHERE code = '{key}'"))
"""
    assert _analyze(source)["primary_issue"] == "sql_injection"


def test_format_map_sql_then_execute():
    source = """
def load(cursor):
    rid = request.args.get("rid")
    sql = "SELECT * FROM rows WHERE id = '{rid}'".format_map({"rid": rid})
    cursor.execute(sql)
"""
    assert _analyze(source)["primary_issue"] == "sql_injection"


def test_built_sql_string_with_executemany_still_sqli():
    source = """
def bulk(cursor):
    label = request.form.get("label")
    sql = "INSERT INTO labels(name) VALUES ('" + label + "')"
    cursor.executemany(sql, [(1,), (2,)])
"""
    assert _analyze(source)["primary_issue"] == "sql_injection"


def test_nested_local_helper_sql_construction():
    source = """
def lookup(cursor):
    def compose(uid):
        return "SELECT * FROM accounts WHERE id = '" + uid + "'"
    user_id = request.args.get("uid")
    cursor.execute(compose(user_id))
"""
    assert _analyze(source)["primary_issue"] == "sql_injection"


def test_parameterized_executemany_remains_safe():
    source = """
def bulk(cursor):
    rows = request.json.get("rows")
    cursor.executemany("INSERT INTO batch(data) VALUES (%s)", rows)
"""
    assert not _has_issue(_analyze(source), "sql_injection")


def test_format_map_html_is_xss():
    source = """
def greet():
    name = request.args.get("name")
    return "<h1>Hi {name}</h1>".format_map({"name": name})
"""
    assert _analyze(source)["primary_issue"] == "xss"


def test_markup_wrapping_escaped_value_is_safe():
    source = """
import html

def box():
    user = request.args.get("user")
    return Markup(html.escape(user))
"""
    assert not _has_issue(_analyze(source), "xss")


def test_httpx_client_context_manager_is_ssrf_sink():
    source = """
from httpx import Client

def fetch():
    loc = request.args.get("loc")
    with Client() as client:
        return client.get(loc).text
"""
    assert _analyze(source)["primary_issue"] == "ssrf"


def test_hostname_or_empty_private_prefix_guard():
    source = """
import requests
from urllib.parse import urlparse

def fetch():
    url = request.args.get("url")
    host = urlparse(url).hostname or ""
    if host.startswith("10."):
        raise ValueError("private")
    return requests.get(url)
"""
    assert not _has_issue(_analyze(source), "ssrf")


def test_inline_urlparse_scheme_https_guard():
    source = """
import requests
from urllib.parse import urlparse
from flask import abort

def fetch():
    u = request.args.get("u")
    if urlparse(u).scheme != "https":
        abort(400)
    return requests.get(u)
"""
    assert not _has_issue(_analyze(source), "ssrf")


def test_allowlist_with_fallthrough_raise_suppresses_ssrf():
    source = """
import requests
from urllib.parse import urlparse

def fetch():
    raw = request.args.get("raw")
    host = urlparse(raw).hostname
    allow = {"img.cdn.com", "static.cdn.com"}
    if host in allow:
        return requests.get(raw)
    raise ValueError("blocked")
"""
    assert not _has_issue(_analyze(source), "ssrf")


def test_allowlist_with_else_raise_suppresses_ssrf():
    source = """
import requests
from urllib.parse import urlparse

def fetch():
    raw = request.args.get("raw")
    host = urlparse(raw).hostname
    allow = {"img.cdn.com"}
    if host in allow:
        return requests.get(raw)
    else:
        raise ValueError("blocked")
"""
    assert not _has_issue(_analyze(source), "ssrf")
