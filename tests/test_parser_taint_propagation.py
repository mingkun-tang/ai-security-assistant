"""Generalized taint propagation and sink resolution (not holdout-specific)."""

from app.engine import analyze
from app.parser.adapter import evidence_to_engine_input
from app.parser.python_parser import parse
from app.source_analysis import analyze_source
from io import StringIO
from pathlib import Path


def _analyze_source_string(source: str, path: str = "sample.py") -> dict:
    tmp = Path(path)
    # analyze_source reads file; use parse + engine for inline snippets
    doc = parse("python", path, source)
    data = evidence_to_engine_input(doc)
    analysis = analyze(data)
    return {
        "primary_issue": analysis.get("issue_type"),
        "findings": analysis.get("findings") or [],
        "data": data,
        "doc": doc,
    }


def test_multihop_assignment_reaches_xss_return():
    source = """
def greet():
    raw = request.args.get("q")
    message = raw
    label = message
    return "<p>" + label + "</p>"
"""
    result = _analyze_source_string(source)
    assert result["primary_issue"] == "xss"


def test_multihop_assignment_reaches_ssrf_request():
    source = """
import requests
def fetch():
    incoming = request.args.get("src")
    target = incoming
    destination = target
    requests.get(destination)
"""
    result = _analyze_source_string(source)
    assert result["primary_issue"] == "ssrf"


def test_json_body_nested_field_reaches_idor_lookup():
    source = """
class Document:
    objects = None

def open_doc():
    payload = request.get_json()
    doc_id = payload.get("document_id")
    return Document.objects.get(id=doc_id)
"""
    result = _analyze_source_string(source)
    assert result["primary_issue"] == "idor"


def test_tainted_join_reaches_sql_execution():
    source = """
def search(cursor):
    column = request.args.get("sort")
    parts = ["SELECT name FROM products ORDER BY ", column]
    cursor.execute("".join(parts))
"""
    result = _analyze_source_string(source)
    assert result["primary_issue"] == "sql_injection"


def test_tainted_path_join_reaches_upload_save():
    source = """
import os
def upload():
    up = request.files["file"]
    path = os.path.join("/var/www/uploads", up.filename)
    up.save(path)
"""
    result = _analyze_source_string(source)
    assert result["primary_issue"] == "file_upload"


def test_aliased_urllib_import_urlopen_is_ssrf_sink():
    source = """
from urllib import request as urlreq
def open_remote():
    loc = request.args.get("loc")
    urlreq.urlopen(loc)
"""
    result = _analyze_source_string(source)
    assert result["primary_issue"] == "ssrf"


def test_weak_scheme_guard_still_ssrf():
    source = """
import requests
from flask import abort, request
from urllib.parse import urlparse

def fetch():
    url = request.args.get("url")
    parsed = urlparse(url or "")
    if parsed.scheme == "http":
        abort(400)
    requests.get(url)
"""
    result = _analyze_source_string(source)
    assert result["primary_issue"] == "ssrf"


def test_strong_hostname_allowlist_suppresses_ssrf():
    source = """
import requests
from flask import abort, request
from urllib.parse import urlparse

ALLOWED_HOSTS = {"cdn.example.com"}

def fetch():
    url = request.args.get("url")
    parsed = urlparse(url or "")
    if parsed.hostname not in ALLOWED_HOSTS:
        abort(403)
    requests.get(url)
"""
    result = _analyze_source_string(source)
    assert result["primary_issue"] != "ssrf"
    assert not any(f.get("issue_type") == "ssrf" for f in result["findings"])


def test_orm_field_filter_not_automatic_idor():
    source = """
class Product:
    objects = None

def find():
    sku = request.args.get("sku")
    return Product.objects.filter(sku=sku).first()
"""
    result = _analyze_source_string(source)
    assert result["primary_issue"] != "idor"


def test_escape_prevents_xss_on_returned_concat():
    source = """
import html
def note():
    body = request.args.get("body")
    escaped = html.escape(body)
    return "<article>" + escaped + "</article>"
"""
    result = _analyze_source_string(source)
    assert result["primary_issue"] != "xss"
