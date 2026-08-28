"""Architecture Sprint #2 — generalized behaviors (not Holdout #2 fixtures)."""

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
        "data": data,
        "doc": doc,
    }


def _has_issue(result: dict, issue: str) -> bool:
    if result["primary_issue"] == issue:
        return True
    return any(f.get("issue_type") == issue for f in result["findings"])


def test_list_append_then_join_reaches_sql_sink():
    source = """
def search(cursor):
    fragments = ["SELECT * FROM items WHERE "]
    clause = request.args.get("clause")
    fragments.append(clause)
    cursor.execute("".join(fragments))
"""
    assert _analyze(source)["primary_issue"] == "sql_injection"


def test_list_literal_join_reaches_html_sink():
    source = """
def render_list():
    label = request.args.get("label")
    chunks = ["<li>", label, "</li>"]
    return "".join(chunks)
"""
    assert _analyze(source)["primary_issue"] == "xss"


def test_orm_extra_where_list_is_sql_injection():
    source = """
class Item:
    objects = None

def filtered():
    predicate = request.args.get("predicate")
    return Item.objects.extra(where=[predicate])
"""
    assert _analyze(source)["primary_issue"] == "sql_injection"


def test_tainted_filename_open_write_webroot_is_upload():
    source = """
def store():
    name = request.files["blob"].filename
    data = request.files["blob"].read()
    open("/var/www/html/files/" + name, "wb").write(data)
"""
    assert _analyze(source)["primary_issue"] == "file_upload"


def test_tainted_filename_pathlib_write_webroot_is_upload():
    source = """
from pathlib import Path

def store():
    name = request.files["blob"].filename
    Path("/var/www/html/files").joinpath(name).write_bytes(request.files["blob"].read())
"""
    assert _analyze(source)["primary_issue"] == "file_upload"


def test_shutil_copy_upload_to_webroot_is_upload():
    source = """
import shutil

def store():
    name = request.files["blob"].filename
    shutil.copy(request.files["blob"], "/var/www/html/" + name)
"""
    assert _analyze(source)["primary_issue"] == "file_upload"


def test_upload_reject_executable_policy_suppresses_danger():
    source = """
def store():
    name = request.files["blob"].filename
    if name.endswith(".py") or name.endswith(".sh"):
        raise ValueError("blocked")
    request.files["blob"].save("/var/secure_vault/" + name)
"""
    assert not _has_issue(_analyze(source), "file_upload")


def test_fixed_name_outside_webroot_not_upload_finding():
    source = """
def store():
    data = request.files["blob"].read()
    open("/var/secure_vault/current.bin", "wb").write(data)
"""
    # Accepts upload but destination filename is not user-controlled.
    result = _analyze(source)
    assert not _has_issue(result, "file_upload")

def test_aiohttp_client_session_get_is_ssrf_sink():
    source = """
import aiohttp

def fetch():
    target = request.args.get("target")
    return aiohttp.ClientSession().get(target)
"""
    assert _analyze(source)["primary_issue"] == "ssrf"


def test_literal_url_path_concat_not_ssrf():
    source = """
import requests

def version():
    base = "https://api.example.com"
    return requests.get(base + "/version")
"""
    assert not _has_issue(_analyze(source), "ssrf")


def test_https_prefix_guard_suppresses_ssrf():
    source = """
import requests

def fetch():
    target = request.args.get("target")
    if not target.startswith("https://"):
        raise ValueError("https only")
    return requests.get(target)
"""
    assert not _has_issue(_analyze(source), "ssrf")


def test_hostname_allowlist_via_alias_suppresses_ssrf():
    source = """
import requests
from urllib.parse import urlparse

ALLOWED = {"cdn.example.com"}

def fetch():
    raw = request.args.get("raw")
    host = urlparse(raw).hostname
    if host not in ALLOWED:
        raise ValueError("host")
    return requests.get(raw)
"""
    assert not _has_issue(_analyze(source), "ssrf")


def test_private_host_prefix_guard_suppresses_ssrf():
    source = """
import requests
from urllib.parse import urlparse

def fetch():
    raw = request.args.get("raw")
    host = urlparse(raw).hostname
    if host.startswith("10."):
        raise ValueError("private")
    return requests.get(raw)
"""
    assert not _has_issue(_analyze(source), "ssrf")


def test_identity_filter_username_without_authz_is_idor():
    source = """
class Account:
    objects = None

def find():
    handle = request.args.get("handle")
    return Account.objects.filter(username=handle).first()
"""
    assert _analyze(source)["primary_issue"] == "idor"


def test_db_query_keyed_by_input_without_authz_is_idor():
    source = """
def load(db):
    key = request.args.get("key")
    return db.query("SELECT * FROM rows WHERE id = ?", key)
"""
    assert _analyze(source)["primary_issue"] == "idor"


def test_ownership_compare_after_lookup_suppresses_idor():
    source = """
class Document:
    objects = None

def load():
    doc_id = request.args.get("doc_id")
    doc = Document.objects.get(id=doc_id)
    if doc.owner_id != session["user_id"]:
        raise PermissionError()
    return doc
"""
    assert not _has_issue(_analyze(source), "idor")


def test_g_user_ownership_compare_suppresses_idor():
    source = """
class Record:
    objects = None

def load():
    rid = request.args.get("rid")
    row = Record.objects.get(id=rid)
    if row.user_id != g.user.id:
        raise PermissionError()
    return row
"""
    assert not _has_issue(_analyze(source), "idor")


def test_admin_role_gate_suppresses_idor():
    source = """
class Account:
    objects = None

def load():
    uid = request.args.get("uid")
    if not g.user.is_admin:
        raise PermissionError()
    return Account.objects.get(id=uid)
"""
    assert not _has_issue(_analyze(source), "idor")


def test_semantic_resource_key_suffix_is_identity():
    source = """
class Ticket:
    objects = None

def load():
    ticket_key = request.args.get("ticket_key")
    return Ticket.objects.filter(ticket_key=ticket_key).first()
"""
    assert _analyze(source)["primary_issue"] == "idor"


def test_non_identity_filter_still_not_idor():
    source = """
class Product:
    objects = None

def find():
    sku = request.args.get("sku")
    return Product.objects.filter(sku=sku).first()
"""
    assert not _has_issue(_analyze(source), "idor")


def test_upload_filename_alias_chain_to_save():
    source = """
def store():
    original = request.files["file"].filename
    renamed = original
    dest = "/var/www/html/" + renamed
    request.files["file"].save(dest)
"""
    assert _analyze(source)["primary_issue"] == "file_upload"
