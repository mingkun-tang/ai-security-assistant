"""Generate adversarial holdout corpus (independent from frozen benchmark)."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "corpus"

CASES: list[dict] = [
    # --- SQL injection ---
    {
        "id": "hold_sqli_v_sqlite_fstring",
        "path": "corpus/sql_injection/hold_sqli_v_sqlite_fstring.py",
        "category": "sql_injection",
        "expected_vulnerable": True,
        "expected_issue_type": "sql_injection",
        "explanation": "sqlite3 execute with f-string embedding request form value.",
        "source": '''
import sqlite3
from flask import request

def lookup(conn):
    email = request.form.get("email")
    conn.execute(f"SELECT id FROM accounts WHERE email = '{email}'")
''',
    },
    {
        "id": "hold_sqli_v_text_format",
        "path": "corpus/sql_injection/hold_sqli_v_text_format.py",
        "category": "sql_injection",
        "expected_vulnerable": True,
        "expected_issue_type": "sql_injection",
        "explanation": "SQLAlchemy-style text() built with str.format and user input.",
        "source": '''
from flask import request

def audit(engine):
    tenant = request.args.get("tenant")
    engine.execute("SELECT * FROM logs WHERE tenant = '{}'".format(tenant))
''',
    },
    {
        "id": "hold_sqli_v_join_fragments",
        "path": "corpus/sql_injection/hold_sqli_v_join_fragments.py",
        "category": "sql_injection",
        "expected_vulnerable": True,
        "expected_issue_type": "sql_injection",
        "explanation": "User-controlled fragments joined into dynamic SQL before execute.",
        "source": '''
from flask import request

def search(cursor):
    column = request.args.get("sort")
    parts = ["SELECT name FROM products ORDER BY ", column]
    cursor.execute("".join(parts))
''',
    },
    {
        "id": "hold_sqli_v_order_by_param",
        "path": "corpus/sql_injection/hold_sqli_v_order_by_param.py",
        "category": "sql_injection",
        "expected_vulnerable": True,
        "expected_issue_type": "sql_injection",
        "explanation": "ORDER BY clause taken directly from query string.",
        "source": '''
from flask import request

def list_items(cursor):
    order = request.args.get("order", "name")
    cursor.execute("SELECT id, name FROM items ORDER BY " + order)
''',
    },
    {
        "id": "hold_sqli_v_second_order",
        "path": "corpus/sql_injection/hold_sqli_v_second_order.py",
        "category": "sql_injection",
        "expected_vulnerable": True,
        "expected_issue_type": "sql_injection",
        "explanation": "Stored user nickname later concatenated into SQL without parameterization.",
        "source": '''
from flask import request

def save_nickname(cursor):
    nick = request.form.get("nick")
    cursor.execute("UPDATE prefs SET nickname = '" + nick + "' WHERE user_id = 1")

def greet(cursor, nickname):
    cursor.execute("SELECT msg FROM greetings WHERE nick = '" + nickname + "'")
''',
    },
    {
        "id": "hold_sqli_s_bound_params",
        "path": "corpus/sql_injection/hold_sqli_s_bound_params.py",
        "category": "sql_injection",
        "expected_vulnerable": False,
        "expected_issue_type": None,
        "explanation": "Named bind parameters isolate user input from SQL text.",
        "source": '''
from flask import request

def lookup(cursor):
    email = request.form.get("email")
    cursor.execute(
        "SELECT id FROM accounts WHERE email = :email",
        {"email": email},
    )
''',
    },
    {
        "id": "hold_sqli_s_orm_filter",
        "path": "corpus/sql_injection/hold_sqli_s_orm_filter.py",
        "category": "sql_injection",
        "expected_vulnerable": False,
        "expected_issue_type": None,
        "explanation": "ORM filter_by passes value as bound data, not SQL text.",
        "source": '''
from flask import request

class Product:
    objects = None

def find():
    sku = request.args.get("sku")
    return Product.objects.filter(sku=sku).first()
''',
    },
    {
        "id": "hold_sqli_s_static_in_clause",
        "path": "corpus/sql_injection/hold_sqli_s_static_in_clause.py",
        "category": "sql_injection",
        "expected_vulnerable": False,
        "expected_issue_type": None,
        "explanation": "IN clause uses only compile-time integer literals.",
        "source": '''
def active(cursor):
    cursor.execute("SELECT id FROM users WHERE status IN (1, 2, 3)")
''',
    },
    {
        "id": "hold_sqli_s_user_in_log",
        "path": "corpus/sql_injection/hold_sqli_s_user_in_log.py",
        "category": "sql_injection",
        "expected_vulnerable": False,
        "expected_issue_type": None,
        "explanation": "User input logged but query uses static SQL.",
        "source": '''
import logging
from flask import request

def audit(cursor):
    user = request.args.get("user")
    logging.info("audit requested for %s", user)
    cursor.execute("SELECT COUNT(*) FROM audits")
''',
    },
    {
        "id": "hold_sqli_s_parameterized_tuple",
        "path": "corpus/sql_injection/hold_sqli_s_parameterized_tuple.py",
        "category": "sql_injection",
        "expected_vulnerable": False,
        "expected_issue_type": None,
        "explanation": "Tuple passed as execute parameters with placeholder SQL.",
        "source": '''
from flask import request

def by_status(cursor):
    status = request.args.get("status")
    cursor.execute("SELECT id FROM orders WHERE status = %s", (status,))
''',
    },
    # --- XSS ---
    {
        "id": "hold_xss_v_style_attr",
        "path": "corpus/xss/hold_xss_v_style_attr.py",
        "category": "xss",
        "expected_vulnerable": True,
        "expected_issue_type": "xss",
        "explanation": "User color injected into inline style attribute via f-string.",
        "source": '''
from flask import request

def badge():
    color = request.args.get("color")
    return f"<span style='color:{color}'>VIP</span>"
''',
    },
    {
        "id": "hold_xss_v_onclick_attr",
        "path": "corpus/xss/hold_xss_v_onclick_attr.py",
        "category": "xss",
        "expected_vulnerable": True,
        "expected_issue_type": "xss",
        "explanation": "User action concatenated into onclick HTML attribute.",
        "source": '''
from flask import request

def button():
    action = request.args.get("action")
    return "<button onclick='" + action + "'>Run</button>"
''',
    },
    {
        "id": "hold_xss_v_mark_safe_chain",
        "path": "corpus/xss/hold_xss_v_mark_safe_chain.py",
        "category": "xss",
        "expected_vulnerable": True,
        "expected_issue_type": "xss",
        "explanation": "mark_safe applied to attacker-controlled banner text.",
        "source": '''
from django.utils.safestring import mark_safe
from flask import request

def banner():
    text = request.args.get("text")
    safe_html = mark_safe(text)
    return safe_html
''',
    },
    {
        "id": "hold_xss_v_multihop_reflect",
        "path": "corpus/xss/hold_xss_v_multihop_reflect.py",
        "category": "xss",
        "expected_vulnerable": True,
        "expected_issue_type": "xss",
        "explanation": "User input copied through locals then reflected in HTML response.",
        "source": '''
from flask import request

def greet():
    raw = request.args.get("q")
    message = raw
    label = message
    return "<p>" + label + "</p>"
''',
    },
    {
        "id": "hold_xss_v_percent_format_html",
        "path": "corpus/xss/hold_xss_v_percent_format_html.py",
        "category": "xss",
        "expected_vulnerable": True,
        "expected_issue_type": "xss",
        "explanation": "Percent-format builds HTML with unescaped user title.",
        "source": '''
from flask import request

def title_block():
    title = request.args.get("title")
    return "<title>%s</title>" % title
''',
    },
    {
        "id": "hold_xss_s_format_html",
        "path": "corpus/xss/hold_xss_s_format_html.py",
        "category": "xss",
        "expected_vulnerable": False,
        "expected_issue_type": None,
        "explanation": "Django format_html escapes interpolated values.",
        "source": '''
from django.utils.html import format_html
from flask import request

def link():
    url = request.args.get("url")
    return format_html("<a href='{}'>home</a>", url)
''',
    },
    {
        "id": "hold_xss_s_escape_multistage",
        "path": "corpus/xss/hold_xss_s_escape_multistage.py",
        "category": "xss",
        "expected_vulnerable": False,
        "expected_issue_type": None,
        "explanation": "html.escape applied before embedding in static HTML wrapper.",
        "source": '''
import html
from flask import request

def note():
    body = request.args.get("body")
    escaped = html.escape(body)
    return "<article>" + escaped + "</article>"
''',
    },
    {
        "id": "hold_xss_s_jsonify",
        "path": "corpus/xss/hold_xss_s_jsonify.py",
        "category": "xss",
        "expected_vulnerable": False,
        "expected_issue_type": None,
        "explanation": "JSON API response does not reflect raw HTML to browser.",
        "source": '''
from flask import jsonify, request

def api_name():
    name = request.args.get("name")
    return jsonify({"name": name})
''',
    },
    {
        "id": "hold_xss_s_redirect",
        "path": "corpus/xss/hold_xss_s_redirect.py",
        "category": "xss",
        "expected_vulnerable": False,
        "expected_issue_type": None,
        "explanation": "Redirect header is not HTML document reflection.",
        "source": '''
from flask import redirect, request

def go():
    target = request.args.get("next")
    return redirect(target)
''',
    },
    {
        "id": "hold_xss_s_template_static",
        "path": "corpus/xss/hold_xss_s_template_static.py",
        "category": "xss",
        "expected_vulnerable": False,
        "expected_issue_type": None,
        "explanation": "Template render with only static context keys.",
        "source": '''
from flask import render_template

def home():
    return render_template("home.html", title="Welcome")
''',
    },
    # --- SSRF ---
    {
        "id": "hold_ssrf_v_httpx_client",
        "path": "corpus/ssrf/hold_ssrf_v_httpx_client.py",
        "category": "ssrf",
        "expected_vulnerable": True,
        "expected_issue_type": "ssrf",
        "explanation": "httpx client performs GET to user-supplied absolute URL.",
        "source": '''
import httpx
from flask import request

def proxy():
    endpoint = request.args.get("endpoint")
    httpx.get(endpoint)
''',
    },
    {
        "id": "hold_ssrf_v_indirect_variable",
        "path": "corpus/ssrf/hold_ssrf_v_indirect_variable.py",
        "category": "ssrf",
        "expected_vulnerable": True,
        "expected_issue_type": "ssrf",
        "explanation": "URL copied through intermediate variable before requests call.",
        "source": '''
import requests
from flask import request

def fetch():
    incoming = request.args.get("src")
    target = incoming
    destination = target
    requests.get(destination)
''',
    },
    {
        "id": "hold_ssrf_v_header_referer",
        "path": "corpus/ssrf/hold_ssrf_v_header_referer.py",
        "category": "ssrf",
        "expected_vulnerable": True,
        "expected_issue_type": "ssrf",
        "explanation": "Server fetches URL read from Referer header.",
        "source": '''
import requests
from flask import request

def preview():
    referer = request.headers.get("Referer")
    requests.get(referer)
''',
    },
    {
        "id": "hold_ssrf_v_weak_scheme_only",
        "path": "corpus/ssrf/hold_ssrf_v_weak_scheme_only.py",
        "category": "ssrf",
        "expected_vulnerable": True,
        "expected_issue_type": "ssrf",
        "explanation": "Only blocks http scheme; https user URLs still reach internal metadata.",
        "source": '''
import requests
from flask import abort, request
from urllib.parse import urlparse

def fetch():
    url = request.args.get("url")
    parsed = urlparse(url or "")
    if parsed.scheme == "http":
        abort(400)
    requests.get(url)
''',
    },
    {
        "id": "hold_ssrf_v_urlopen_alias",
        "path": "corpus/ssrf/hold_ssrf_v_urlopen_alias.py",
        "category": "ssrf",
        "expected_vulnerable": True,
        "expected_issue_type": "ssrf",
        "explanation": "urllib.request.urlopen called with user-controlled location.",
        "source": '''
from urllib import request as urlreq
from flask import request

def open_remote():
    loc = request.args.get("loc")
    urlreq.urlopen(loc)
''',
    },
    {
        "id": "hold_ssrf_s_fixed_service",
        "path": "corpus/ssrf/hold_ssrf_s_fixed_service.py",
        "category": "ssrf",
        "expected_vulnerable": False,
        "expected_issue_type": None,
        "explanation": "Outbound request uses compile-time constant service URL.",
        "source": '''
import requests

def health():
    requests.get("https://status.example.com/api/health")
''',
    },
    {
        "id": "hold_ssrf_s_allowlist_netloc",
        "path": "corpus/ssrf/hold_ssrf_s_allowlist_netloc.py",
        "category": "ssrf",
        "expected_vulnerable": False,
        "expected_issue_type": None,
        "explanation": "Hostname allowlist enforced before requests.get.",
        "source": '''
import requests
from flask import abort, request
from urllib.parse import urlparse

ALLOWED_HOSTS = {"cdn.example.com", "api.example.com"}

def fetch():
    url = request.args.get("url")
    parsed = urlparse(url or "")
    if parsed.hostname not in ALLOWED_HOSTS:
        abort(403)
    requests.get(url)
''',
    },
    {
        "id": "hold_ssrf_s_https_required",
        "path": "corpus/ssrf/hold_ssrf_s_https_required.py",
        "category": "ssrf",
        "expected_vulnerable": False,
        "expected_issue_type": None,
        "explanation": "HTTPS-only scheme guard with abort before network call.",
        "source": '''
import requests
from flask import abort, request
from urllib.parse import urlparse

def fetch():
    url = request.form.get("callback")
    parsed = urlparse(url or "")
    if parsed.scheme != "https":
        abort(400)
    requests.get(url)
''',
    },
    {
        "id": "hold_ssrf_s_user_url_in_html",
        "path": "corpus/ssrf/hold_ssrf_s_user_url_in_html.py",
        "category": "ssrf",
        "expected_vulnerable": False,
        "expected_issue_type": None,
        "explanation": "User URL embedded in HTML anchor only; server does not fetch it.",
        "source": '''
from flask import request

def page():
    href = request.args.get("href")
    return "<a href='" + href + "'>external</a>"
''',
    },
    {
        "id": "hold_ssrf_s_session_validated",
        "path": "corpus/ssrf/hold_ssrf_s_session_validated.py",
        "category": "ssrf",
        "expected_vulnerable": False,
        "expected_issue_type": None,
        "explanation": "HTTP session client with allowlisted host validation before GET.",
        "source": '''
from flask import abort, request
from urllib.parse import urlparse

ALLOWED = {"hooks.example.com"}

def pull(session):
    url = request.args.get("hook")
    parsed = urlparse(url or "")
    if parsed.hostname not in ALLOWED:
        abort(400)
    session.get(url)
''',
    },
    # --- File upload ---
    {
        "id": "hold_upload_v_double_extension",
        "path": "corpus/file_upload/hold_upload_v_double_extension.py",
        "category": "file_upload",
        "expected_vulnerable": True,
        "expected_issue_type": "file_upload",
        "explanation": "User filename saved under webroot without type validation.",
        "source": '''
from flask import request

def upload():
    doc = request.files["doc"]
    doc.save("public/docs/" + doc.filename)
''',
    },
    {
        "id": "hold_upload_v_path_join",
        "path": "corpus/file_upload/hold_upload_v_path_join.py",
        "category": "file_upload",
        "expected_vulnerable": True,
        "expected_issue_type": "file_upload",
        "explanation": "os.path.join with user filename under uploads directory.",
        "source": '''
import os
from flask import request

def upload():
    up = request.files["file"]
    path = os.path.join("/var/www/uploads", up.filename)
    up.save(path)
''',
    },
    {
        "id": "hold_upload_v_size_only",
        "path": "corpus/file_upload/hold_upload_v_size_only.py",
        "category": "file_upload",
        "expected_vulnerable": True,
        "expected_issue_type": "file_upload",
        "explanation": "Only max size checked; executable extension still saved to static.",
        "source": '''
from flask import request

def upload():
    blob = request.files["blob"]
    if blob.content_length and blob.content_length > 5000000:
        return "too large", 400
    blob.save("static/media/" + blob.filename)
''',
    },
    {
        "id": "hold_upload_v_content_type_trust",
        "path": "corpus/file_upload/hold_upload_v_content_type_trust.py",
        "category": "file_upload",
        "expected_vulnerable": True,
        "expected_issue_type": "file_upload",
        "explanation": "Trusts client Content-Type header instead of extension policy.",
        "source": '''
from flask import request

def upload():
    pic = request.files["pic"]
    if pic.mimetype == "image/png":
        pic.save("/srv/app/uploads/" + pic.filename)
''',
    },
    {
        "id": "hold_upload_v_tmp_user_ext",
        "path": "corpus/file_upload/hold_upload_v_tmp_user_ext.py",
        "category": "file_upload",
        "expected_vulnerable": True,
        "expected_issue_type": "file_upload",
        "explanation": "Writes upload to /tmp using attacker-controlled filename suffix.",
        "source": '''
from flask import request

def stash():
    f = request.files.get("f")
    f.save("/tmp/" + f.filename)
''',
    },
    {
        "id": "hold_upload_s_png_guard",
        "path": "corpus/file_upload/hold_upload_s_png_guard.py",
        "category": "file_upload",
        "expected_vulnerable": False,
        "expected_issue_type": None,
        "explanation": "PNG extension required before save to non-webroot path.",
        "source": '''
from flask import abort, request

def upload():
    img = request.files["img"]
    if not img.filename.endswith(".png"):
        abort(400)
    img.save("/data/images/archive.png")
''',
    },
    {
        "id": "hold_upload_s_reject_php",
        "path": "corpus/file_upload/hold_upload_s_reject_php.py",
        "category": "file_upload",
        "expected_vulnerable": False,
        "expected_issue_type": None,
        "explanation": "PHP extension rejected; fixed safe destination path.",
        "source": '''
from flask import abort, request

def upload():
    f = request.files["f"]
    if f.filename.endswith(".php"):
        abort(400)
    f.save("/var/storage/blob.bin")
''',
    },
    {
        "id": "hold_upload_s_no_disk_write",
        "path": "corpus/file_upload/hold_upload_s_no_disk_write.py",
        "category": "file_upload",
        "expected_vulnerable": False,
        "expected_issue_type": None,
        "explanation": "File accepted to memory buffer only; no save() call.",
        "source": '''
from flask import request

def inspect():
    f = request.files["f"]
    data = f.read()
    return {"bytes": len(data)}
''',
    },
    {
        "id": "hold_upload_s_secure_name",
        "path": "corpus/file_upload/hold_upload_s_secure_name.py",
        "category": "file_upload",
        "expected_vulnerable": False,
        "expected_issue_type": None,
        "explanation": "werkzeug secure_filename strips path segments; constant basename.",
        "source": '''
from flask import request
from werkzeug.utils import secure_filename

def upload():
    f = request.files["f"]
    name = secure_filename(f.filename)
    f.save("/var/data/" + name)
''',
    },
    {
        "id": "hold_upload_s_lookalike_log",
        "path": "corpus/file_upload/hold_upload_s_lookalike_log.py",
        "category": "file_upload",
        "expected_vulnerable": False,
        "expected_issue_type": None,
        "explanation": "Logs filename metadata without persisting uploaded bytes.",
        "source": '''
import logging
from flask import request

def log_meta():
    f = request.files["f"]
    logging.info("received upload name=%s", f.filename)
    return "ok"
''',
    },
    # --- IDOR ---
    {
        "id": "hold_idor_v_post_user_id",
        "path": "corpus/idor/hold_idor_v_post_user_id.py",
        "category": "idor",
        "expected_vulnerable": True,
        "expected_issue_type": "idor",
        "explanation": "POST body user_id used to load profile without ownership check.",
        "source": '''
from flask import request

class Profile:
    objects = None

def show():
    uid = request.form.get("user_id")
    return Profile.objects.get(id=uid)
''',
    },
    {
        "id": "hold_idor_v_email_lookup",
        "path": "corpus/idor/hold_idor_v_email_lookup.py",
        "category": "idor",
        "expected_vulnerable": True,
        "expected_issue_type": "idor",
        "explanation": "Email from query used to fetch user record without authz.",
        "source": '''
from flask import request

class User:
    objects = None

def find_user():
    email = request.args.get("email")
    return User.objects.filter(email=email).first()
''',
    },
    {
        "id": "hold_idor_v_delete_by_id",
        "path": "corpus/idor/hold_idor_v_delete_by_id.py",
        "category": "idor",
        "expected_vulnerable": True,
        "expected_issue_type": "idor",
        "explanation": "Destructive ORM delete keyed only by request parameter.",
        "source": '''
from flask import request

class Invoice:
    objects = None

def remove():
    invoice_id = request.args.get("invoice_id")
    Invoice.objects.filter(id=invoice_id).delete()
''',
    },
    {
        "id": "hold_idor_v_json_body_id",
        "path": "corpus/idor/hold_idor_v_json_body_id.py",
        "category": "idor",
        "expected_vulnerable": True,
        "expected_issue_type": "idor",
        "explanation": "JSON document id from request body drives ORM get.",
        "source": '''
from flask import request

class Document:
    objects = None

def open_doc():
    payload = request.get_json()
    doc_id = payload.get("document_id")
    return Document.objects.get(id=doc_id)
''',
    },
    {
        "id": "hold_idor_v_filter_no_owner",
        "path": "corpus/idor/hold_idor_v_filter_no_owner.py",
        "category": "idor",
        "expected_vulnerable": True,
        "expected_issue_type": "idor",
        "explanation": "Filter uses user-supplied account id without session ownership check.",
        "source": '''
from flask import request

class Account:
    objects = None

def balance():
    account_id = request.args.get("account_id")
    return Account.objects.filter(id=account_id).first()
''',
    },
    {
        "id": "hold_idor_s_owner_compare",
        "path": "corpus/idor/hold_idor_s_owner_compare.py",
        "category": "idor",
        "expected_vulnerable": False,
        "expected_issue_type": None,
        "explanation": "Record returned only when owner_id matches current_user.",
        "source": '''
from flask import abort, request
from flask_login import current_user

class Note:
    objects = None

def read():
    note_id = request.args.get("id")
    note = Note.objects.get(id=note_id)
    if note.owner_id != current_user.id:
        abort(403)
    return note
''',
    },
    {
        "id": "hold_idor_s_filter_current_user",
        "path": "corpus/idor/hold_idor_s_filter_current_user.py",
        "category": "idor",
        "expected_vulnerable": False,
        "expected_issue_type": None,
        "explanation": "Query scoped to authenticated user id from session context.",
        "source": '''
from flask_login import current_user

class Order:
    objects = None

def my_orders():
    return Order.objects.filter(user_id=current_user.id).all()
''',
    },
    {
        "id": "hold_idor_s_guard_before_update",
        "path": "corpus/idor/hold_idor_s_guard_before_update.py",
        "category": "idor",
        "expected_vulnerable": False,
        "expected_issue_type": None,
        "explanation": "Ownership compare before persisting update.",
        "source": '''
from flask import abort, request
from flask_login import current_user

class Settings:
    objects = None

def update():
    settings_id = request.form.get("id")
    row = Settings.objects.get(id=settings_id)
    if row.user_id != current_user.id:
        abort(403)
    row.theme = request.form.get("theme")
    row.save()
''',
    },
    {
        "id": "hold_idor_s_static_lookup",
        "path": "corpus/idor/hold_idor_s_static_lookup.py",
        "category": "idor",
        "expected_vulnerable": False,
        "expected_issue_type": None,
        "explanation": "Lookup uses constant identifier, not user input.",
        "source": '''
class Config:
    objects = None

def site_config():
    return Config.objects.get(id=1)
''',
    },
    {
        "id": "hold_idor_s_lookalike_public",
        "path": "corpus/idor/hold_idor_s_lookalike_public.py",
        "category": "idor",
        "expected_vulnerable": False,
        "expected_issue_type": None,
        "explanation": "Public catalog listing without per-user object access.",
        "source": '''
class Product:
    objects = None

def catalog():
    return Product.objects.filter(is_public=True).all()
''',
    },
]


def main() -> None:
    manifest_cases = []
    for case in CASES:
        rel = case["path"]
        dest = ROOT / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        source = case["source"].strip() + "\n"
        dest.write_text(source, encoding="utf-8")
        manifest_cases.append(
            {
                "id": case["id"],
                "path": rel,
                "language": "python",
                "category": case["category"],
                "expected_vulnerable": case["expected_vulnerable"],
                "expected_issue_type": case["expected_issue_type"],
                "explanation": case["explanation"],
            }
        )

    payload = {
        "version": "1.0",
        "description": "Adversarial holdout corpus (independent from frozen benchmark)",
        "scanner": "analyze_source",
        "cases": manifest_cases,
    }
    (ROOT / "ground_truth.json").write_text(
        json.dumps(payload, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"Wrote {len(manifest_cases)} holdout cases under {ROOT}")


if __name__ == "__main__":
    main()
