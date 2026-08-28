"""One-time corpus generator for evaluation benchmark. Run from repo root."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "benchmark"
CORPUS = ROOT / "corpus"

CASES: list[dict] = []

FILES: dict[str, str] = {
    # SQL injection — vulnerable
    "sql_injection/vuln_concat_execute.py": '''from flask import request

def search(cursor):
    user_id = request.args.get("id")
    cursor.execute("SELECT * FROM users WHERE id = " + user_id)
''',
    "sql_injection/vuln_fstring_execute.py": '''from flask import request

def search(cursor):
    user_id = request.args.get("q")
    cursor.execute(f"SELECT * FROM users WHERE name = {user_id}")
''',
    "sql_injection/vuln_format_execute.py": '''from flask import request

def search(cursor):
    user_id = request.args.get("id")
    cursor.execute("SELECT * FROM users WHERE id = {}".format(user_id))
''',
    "sql_injection/vuln_percent_format.py": '''from flask import request

def search(cursor):
    user_id = request.args.get("id")
    cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)
''',
    "sql_injection/vuln_join_query.py": '''from flask import request

def search(cursor):
    table = request.args.get("table")
    cursor.execute("SELECT * FROM " + table)
''',
    "sql_injection/vuln_concat_in_where.py": '''from flask import request

def filter_users(cursor):
    status = request.form.get("status")
    cursor.execute("UPDATE users SET active=1 WHERE status = '" + status + "'")
''',
    # SQL injection — safe
    "sql_injection/safe_parameterized.py": '''from flask import request

def search(cursor):
    user_id = request.args.get("id")
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
''',
    "sql_injection/safe_static_query.py": '''def list_users(cursor):
    cursor.execute("SELECT id, email FROM users LIMIT 100")
''',
    "sql_injection/safe_parameterized_tuple.py": '''from flask import request

def search(cursor):
    email = request.args.get("email")
    cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
''',
    "sql_injection/safe_no_user_input.py": '''def count_users(cursor):
    cursor.execute("SELECT COUNT(*) FROM users")
''',
    "sql_injection/safe_literal_filter.py": '''def active_users(cursor):
    cursor.execute("SELECT * FROM users WHERE active = 1")
''',
    "sql_injection/safe_named_params.py": '''from flask import request

def search(cursor):
    user_id = request.args.get("id")
    cursor.execute("SELECT * FROM users WHERE id = %(id)s", {"id": user_id})
''',
    # XSS — vulnerable
    "xss/vuln_render_template_input.py": '''from flask import render_template, request

def hello():
    name = request.args.get("name")
    return render_template("hello.html", name=name)
''',
    "xss/vuln_template_string.py": '''from flask import request

def greet():
    name = request.args.get("name")
    return f"<h1>Hello {name}</h1>"
''',
    "xss/vuln_markup_concat.py": '''from flask import request

def comment():
    text = request.args.get("comment")
    return "<div>" + text + "</div>"
''',
    "xss/vuln_jinja_style_render.py": '''from flask import render_template_string, request

def preview():
    body = request.args.get("body")
    return render_template_string("<p>{{ body }}</p>", body=body)
''',
    "xss/vuln_unescaped_variable.py": '''from flask import request

def badge():
    label = request.args.get("label")
    return "<span class='badge'>" + label + "</span>"
''',
    "xss/vuln_url_in_html.py": '''from flask import request

def link():
    target = request.args.get("url")
    return "<a href='" + target + "'>click</a>"
''',
    # XSS — safe
    "xss/safe_static_template.py": '''from flask import render_template

def hello():
    return render_template("hello.html")
''',
    "xss/safe_markupsafe_escape.py": '''from flask import render_template, request
from markupsafe import escape

def hello():
    name = request.args.get("name")
    return render_template("hello.html", name=escape(name))
''',
    "xss/safe_no_reflection.py": '''from flask import request

def hello():
    name = request.args.get("name")
    return {"greeting": "hello", "ignored": name is not None}
''',
    "xss/safe_json_response.py": '''from flask import jsonify, request

def hello():
    name = request.args.get("name")
    return jsonify({"name": name})
''',
    "xss/safe_hardcoded_html.py": '''def banner():
    return "<h1>Welcome</h1>"
''',
    "xss/safe_escaped_concat.py": '''from flask import request
from markupsafe import escape

def hello():
    name = request.args.get("name")
    safe = escape(name)
    return "<p>" + safe + "</p>"
''',
    # SSRF — vulnerable
    "ssrf/vuln_requests_get_input.py": '''import requests
from flask import request

def fetch():
    url = request.args.get("url")
    requests.get(url)
''',
    "ssrf/vuln_concat_url.py": '''import requests
from flask import request

def fetch():
    host = request.args.get("host")
    requests.get("http://" + host + "/api")
''',
    "ssrf/vuln_post_url.py": '''import requests
from flask import request

def proxy():
    target = request.form.get("callback")
    requests.post(target, data={"ok": True})
''',
    "ssrf/vuln_fstring_url.py": '''import requests
from flask import request

def fetch():
    path = request.args.get("path")
    requests.get(f"https://internal.service/{path}")
''',
    "ssrf/vuln_urllib_input.py": '''import urllib.request
from flask import request

def fetch():
    url = request.args.get("url")
    urllib.request.urlopen(url)
''',
    "ssrf/vuln_session_url.py": '''import requests
from flask import request

def fetch(session):
    url = request.args.get("redirect")
    session.get(url)
''',
    # SSRF — safe
    "ssrf/safe_literal_url.py": '''import requests

def health():
    requests.get("https://status.example.com/health")
''',
    "ssrf/safe_allowlist_host.py": '''import requests
from flask import abort, request
from urllib.parse import urlparse

ALLOWED = {"api.example.com"}

def fetch():
    url = request.args.get("url")
    parsed = urlparse(url or "")
    if parsed.hostname not in ALLOWED:
        abort(400)
    requests.get(url)
''',
    "ssrf/safe_fixed_endpoint.py": '''import requests

def metrics():
    requests.get("https://metrics.internal/v1/summary")
''',
    "ssrf/safe_no_network.py": '''from flask import request

def preview():
    url = request.args.get("url")
    return {"received": url is not None}
''',
    "ssrf/safe_https_only_literal.py": '''import requests

def ping():
    requests.get("https://example.com/ping")
''',
    "ssrf/safe_validated_scheme.py": '''import requests
from flask import abort, request
from urllib.parse import urlparse

def fetch():
    url = request.args.get("url")
    parsed = urlparse(url or "")
    if parsed.scheme != "https":
        abort(400)
    requests.get(url)
''',
    # File upload — vulnerable
    "file_upload/vuln_user_filename_webroot.py": '''from flask import request

def upload():
    uploaded = request.files["file"]
    uploaded.save("static/uploads/" + uploaded.filename)
''',
    "file_upload/vuln_executable_name.py": '''from flask import request

def upload():
    f = request.files.get("payload")
    f.save("/var/www/uploads/" + f.filename)
''',
    "file_upload/vuln_no_validation.py": '''from flask import request

def upload():
    data = request.files["doc"]
    data.save(data.filename)
''',
    "file_upload/vuln_public_path.py": '''from flask import request

def upload():
    blob = request.files["image"]
    blob.save("public/" + blob.filename)
''',
    "file_upload/vuln_concat_path.py": '''from flask import request

def upload():
    name = request.files["file"].filename
    request.files["file"].save("/tmp/" + name)
''',
    "file_upload/vuln_script_extension.py": '''from flask import request

def upload():
    up = request.files["script"]
    up.save("uploads/" + up.filename)
''',
    # File upload — safe
    "file_upload/safe_fixed_filename.py": '''from flask import request

def upload():
    uploaded = request.files.get("avatar")
    if uploaded.filename.endswith(".jpg"):
        uploaded.save("/var/uploads/photo.jpg")
''',
    "file_upload/safe_extension_check.py": '''from flask import request

def upload():
    f = request.files["file"]
    if f.filename.endswith(".png"):
        f.save("/data/images/safe.png")
''',
    "file_upload/safe_no_save.py": '''from flask import request

def upload():
    f = request.files.get("file")
    return {"size": len(f.read()) if f else 0}
''',
    "file_upload/safe_outside_webroot.py": '''from flask import request

def upload():
    f = request.files["doc"]
    f.save("/var/secure_storage/document.pdf")
''',
    "file_upload/safe_random_name.py": '''from flask import request
import uuid

def upload():
    f = request.files["photo"]
    f.save(f"/var/uploads/{uuid.uuid4().hex}.jpg")
''',
    "file_upload/safe_reject_executable.py": '''from flask import request, abort

def upload():
    f = request.files["file"]
    if f.filename.endswith(".exe"):
        abort(400)
    f.save("/var/uploads/image.jpg")
''',
    # IDOR — vulnerable
    "idor/vuln_get_by_id.py": '''from flask import request

class User:
    objects = None

def view_profile():
    user_id = request.args.get("id")
    user = User.objects.get(id=user_id)
    return user
''',
    "idor/vuln_update_other_user.py": '''from flask import request

class User:
    objects = None

def update_email():
    user_id = request.args.get("user_id")
    email = request.form.get("email")
    user = User.objects.get(id=user_id)
    user.email = email
    user.save()
''',
    "idor/vuln_delete_by_param.py": '''from flask import request

class Account:
    objects = None

def delete_account():
    account_id = request.args.get("account_id")
    Account.objects.filter(id=account_id).delete()
''',
    "idor/vuln_fetch_record.py": '''from flask import request

class Order:
    objects = None

def order_detail():
    order_id = request.args.get("order_id")
    return Order.objects.get(id=order_id)
''',
    "idor/vuln_path_id.py": '''from flask import request

class Document:
    objects = None

def open_doc():
    doc_id = request.view_args.get("doc_id")
    return Document.objects.get(id=doc_id)
''',
    "idor/vuln_profile_lookup.py": '''from flask import request

class Profile:
    objects = None

def show():
    pid = request.args.get("profile_id")
    return Profile.objects.get(id=pid)
''',
    # IDOR — safe
    "idor/safe_ownership_check.py": '''from flask import request

class User:
    objects = None

def view_profile(current_user):
    user_id = request.args.get("id")
    user = User.objects.get(id=user_id)
    if user.id == current_user.id:
        return user
    return None
''',
    "idor/safe_current_user_only.py": '''from flask import request

class User:
    objects = None

def my_profile(current_user):
    return User.objects.get(id=current_user.id)
''',
    "idor/safe_guard_before_update.py": '''from flask import request

class User:
    objects = None

def update_email(current_user):
    user_id = request.args.get("user_id")
    user = User.objects.get(id=user_id)
    if user.id != current_user.id:
        return None
    user.email = request.form.get("email")
    user.save()
''',
    "idor/safe_filter_owner.py": '''from flask import request

class Order:
    objects = None

def my_orders(current_user):
    return Order.objects.filter(user_id=current_user.id)
''',
    "idor/safe_no_user_lookup.py": '''def list_public_posts():
    return [{"id": 1, "title": "Hello"}]
''',
    "idor/safe_static_resource.py": '''def health():
    return {"status": "ok"}
''',
}

EXPLANATIONS: dict[str, str] = {
    "vuln_concat_execute": "User input concatenated into SQL execute().",
    "vuln_fstring_execute": "F-string builds SQL with user input.",
    "vuln_format_execute": "str.format injects user input into SQL.",
    "vuln_percent_format": "Percent formatting with user input in SQL.",
    "vuln_join_query": "User-controlled table name in SQL.",
    "vuln_concat_in_where": "Concatenated form input in UPDATE WHERE clause.",
    "safe_parameterized": "Parameterized query binds user input safely.",
    "safe_static_query": "Static SQL with no user input.",
    "safe_parameterized_tuple": "Tuple parameters for execute().",
    "safe_no_user_input": "Count query without user input.",
    "safe_literal_filter": "Literal filter only.",
    "safe_named_params": "Named parameter binding.",
    "vuln_render_template_input": "User input passed to template without escaping.",
    "vuln_template_string": "User input reflected in HTML response.",
    "vuln_markup_concat": "HTML built via string concatenation.",
    "vuln_jinja_style_render": "User input in render_template_string.",
    "vuln_unescaped_variable": "User label concatenated into HTML.",
    "vuln_url_in_html": "User URL in href without validation.",
    "safe_static_template": "Template without user-controlled output.",
    "safe_markupsafe_escape": "markupsafe.escape before template.",
    "safe_no_reflection": "Input not reflected in HTML.",
    "safe_json_response": "JSON response not HTML sink.",
    "safe_hardcoded_html": "Static HTML only.",
    "safe_escaped_concat": "Escaped before HTML concat.",
    "vuln_requests_get_input": "requests.get with user URL.",
    "vuln_concat_url": "Host concatenated into outbound URL.",
    "vuln_post_url": "User callback URL in requests.post.",
    "vuln_fstring_url": "F-string builds request URL from input.",
    "vuln_urllib_input": "urllib opens user-controlled URL.",
    "vuln_session_url": "Session GET to user redirect URL.",
    "safe_literal_url": "Fixed HTTPS endpoint only.",
    "safe_allowlist_host": "Allowlisted host before request.",
    "safe_fixed_endpoint": "Internal metrics URL is fixed.",
    "safe_no_network": "No outbound request made.",
    "safe_https_only_literal": "Literal HTTPS ping.",
    "safe_validated_scheme": "Scheme validated before fetch.",
    "vuln_user_filename_webroot": "User filename saved under web root.",
    "vuln_executable_name": "User filename under web uploads.",
    "vuln_no_validation": "Raw filename save without checks.",
    "vuln_public_path": "Upload saved to public path with user name.",
    "vuln_concat_path": "Concatenated path with user filename.",
    "vuln_script_extension": "Unvalidated upload filename.",
    "safe_fixed_filename": "Fixed destination filename.",
    "safe_extension_check": "Extension checked before save.",
    "safe_no_save": "File read but not persisted.",
    "safe_outside_webroot": "Saved outside web root with fixed name.",
    "safe_random_name": "Random server-side filename.",
    "safe_reject_executable": "Executable extension rejected.",
    "vuln_get_by_id": "Object fetched by user-supplied id without ownership check.",
    "vuln_update_other_user": "Update by user_id without ownership validation.",
    "vuln_delete_by_param": "Delete by account_id from request.",
    "vuln_fetch_record": "Order fetched by user order_id only.",
    "vuln_path_id": "Document opened by path id without auth.",
    "vuln_profile_lookup": "Profile lookup by user profile_id.",
    "safe_ownership_check": "Ownership verified before returning user.",
    "safe_current_user_only": "Uses current_user id only.",
    "safe_guard_before_update": "Ownership guard before update.",
    "safe_filter_owner": "Query filtered to current user.",
    "safe_no_user_lookup": "Static public data only.",
    "safe_static_resource": "No user-specific data access.",
}


def main() -> None:
    CORPUS.mkdir(parents=True, exist_ok=True)
    cases = []
    for rel_path, source in FILES.items():
        category = rel_path.split("/")[0]
        filename = rel_path.split("/")[1]
        stem = filename.replace(".py", "")
        is_vuln = stem.startswith("vuln_")
        case_id = f"{category}-{stem}"
        file_path = CORPUS / rel_path
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_text(source, encoding="utf-8")
        cases.append(
            {
                "id": case_id,
                "path": f"corpus/{rel_path}",
                "language": "python",
                "category": category,
                "expected_vulnerable": is_vuln,
                "expected_issue_type": category if is_vuln else None,
                "explanation": EXPLANATIONS.get(stem, ""),
            }
        )

    manifest = {
        "version": "1.0",
        "description": "Deterministic source-analysis benchmark corpus",
        "scanner": "analyze_source",
        "cases": cases,
    }
    (ROOT / "ground_truth.json").write_text(
        json.dumps(manifest, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"Wrote {len(cases)} cases to {ROOT}")


if __name__ == "__main__":
    main()
