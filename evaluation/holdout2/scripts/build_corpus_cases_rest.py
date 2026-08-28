"""Remaining holdout2 cases (XSS, SSRF, file upload, IDOR)."""


def register_rest(add) -> None:
    # XSS (20)
    add(
        "xss",
        "u2_xss_v_markup_format_user",
        True,
        'def greet():\n    who = request.args.get("who")\n    return Markup("<h2>Hello {}</h2>".format(who))',
        "Markup.format embeds user in HTML without escape.",
    )
    add(
        "xss",
        "u2_xss_v_nested_span_concat",
        True,
        'def badge():\n    label = request.args.get("label")\n    inner = "<span>" + label + "</span>"\n    return "<div>" + inner + "</div>"',
        "Nested HTML concatenation reflects user label.",
    )
    add(
        "xss",
        "u2_xss_v_triple_hop_render",
        True,
        'def panel():\n    t = request.args.get("t")\n    u = t\n    v = u\n    return render_template_string("<p>{{ v }}</p>", v=v)',
        "Triple-hop taint into render_template_string.",
    )
    add(
        "xss",
        "u2_xss_v_json_field_in_html",
        True,
        'def preview():\n    body = request.json.get("body")\n    return "<article>" + body + "</article>"',
        "JSON body field concatenated into HTML response.",
    )
    add(
        "xss",
        "u2_xss_v_fstring_div",
        True,
        'def card():\n    title = request.form.get("title")\n    return f"<div class=card>{title}</div>"',
        "f-string builds HTML div with user title.",
    )
    add(
        "xss",
        "u2_xss_v_list_join_tags",
        True,
        'def chips():\n    items = request.args.get("items")\n    parts = ["<ul>", items, "</ul>"]\n    return "".join(parts)',
        "Joined list places user items inside ul.",
    )
    add(
        "xss",
        "u2_xss_v_error_message_reflect",
        True,
        'def fail():\n    msg = request.args.get("msg")\n    return "<p class=err>" + msg + "</p>"',
        "Error message from query reflected in HTML.",
    )
    add(
        "xss",
        "u2_xss_v_template_percent",
        True,
        'def note():\n    text = request.form.get("text")\n    return "<em>%s</em>" % text',
        "Percent formatting embeds user in em tag.",
    )
    add(
        "xss",
        "u2_xss_v_attr_value_concat",
        True,
        'def link():\n    dest = request.args.get("dest")\n    return "<a href=\'" + dest + "\'>go</a>"',
        "User value in href attribute via concatenation.",
    )
    add(
        "xss",
        "u2_xss_v_render_string_kw",
        True,
        'def snippet():\n    html = request.args.get("html")\n    return render_template_string("{{ content }}", content=html)',
        "render_template_string with user HTML as template variable.",
    )

    add(
        "xss",
        "u2_xss_s_jsonify_message",
        False,
        'def api_msg():\n    m = request.args.get("m")\n    return jsonify({"message": m})',
        "JSON API response, not HTML reflection.",
    )
    add(
        "xss",
        "u2_xss_s_markupsafe_escape_chain",
        False,
        'def safe_greet():\n    who = request.args.get("who")\n    return "<h2>" + escape(who) + "</h2>"',
        "markupsafe escape applied before HTML concat.",
    )
    add(
        "xss",
        "u2_xss_s_static_template_file",
        False,
        'def home():\n    return render_template("home.html")',
        "Static template file without user data.",
    )
    add(
        "xss",
        "u2_xss_s_no_output",
        False,
        'def ingest():\n    blob = request.get_data()\n    store(blob)\n    return "ok"',
        "Raw body stored, no HTML output.",
    )
    add(
        "xss",
        "u2_xss_s_escaped_fstring",
        False,
        'def safe_card():\n    title = request.form.get("title")\n    return f"<div>{escape(title)}</div>"',
        "f-string with escaped user title.",
    )
    add(
        "xss",
        "u2_xss_s_redirect_only",
        False,
        'def bounce():\n    target = request.args.get("target")\n    return redirect(target)',
        "Redirect header, not HTML body reflection.",
    )
    add(
        "xss",
        "u2_xss_s_hardcoded_markup",
        False,
        'def banner():\n    return Markup("<strong>Welcome</strong>")',
        "Static Markup only.",
    )
    add(
        "xss",
        "u2_xss_s_template_static_ctx",
        False,
        'def about():\n    return render_template("about.html", year=2026)',
        "Template with static context only.",
    )
    add(
        "xss",
        "u2_xss_s_user_in_comment_only",
        False,
        'def debug_note():\n    note = request.args.get("note")\n    logging.info("note=%s", note)\n    return "<p>logged</p>"',
        "User input logged, static HTML returned.",
    )
    add(
        "xss",
        "u2_xss_s_bleach_clean",
        False,
        'def safe_article():\n    body = request.json.get("body")\n    clean = bleach.clean(body)\n    return "<article>" + clean + "</article>"',
        "bleach.clean before HTML concat (sanitized).",
    )

    # SSRF (20)
    add(
        "ssrf",
        "u2_ssrf_v_httpx_client",
        True,
        'import httpx\n\ndef probe():\n    endpoint = request.args.get("endpoint")\n    return httpx.get(endpoint).text',
        "httpx.get on user endpoint.",
    )
    add(
        "ssrf",
        "u2_ssrf_v_aiohttp_session",
        True,
        'import aiohttp\n\ndef fetch():\n    url = request.form.get("url")\n    return aiohttp.ClientSession().get(url)',
        "aiohttp session GET with user URL.",
    )
    add(
        "ssrf",
        "u2_ssrf_v_double_assign_url",
        True,
        'def mirror():\n    u = request.args.get("u")\n    w = u\n    return requests.get(w).content',
        "Double assignment chain into requests.get.",
    )
    add(
        "ssrf",
        "u2_ssrf_v_json_callback",
        True,
        'def callback():\n    cb = request.json.get("callback")\n    return urllib.request.urlopen(cb).read()',
        "JSON callback URL opened via urllib.",
    )
    add(
        "ssrf",
        "u2_ssrf_v_fstring_requests",
        True,
        'def pull():\n    host = request.args.get("host")\n    return requests.get(f"http://{host}/status")',
        "f-string host in requests URL.",
    )
    add(
        "ssrf",
        "u2_ssrf_v_concat_scheme_host",
        True,
        'def open_link():\n    scheme = request.args.get("scheme")\n    host = request.args.get("host")\n    return requests.get(scheme + "://" + host)',
        "Concatenated scheme and host in URL.",
    )
    add(
        "ssrf",
        "u2_ssrf_v_post_body_url",
        True,
        'def relay():\n    target = request.form.get("target")\n    return requests.post(target, data={"ping": "1"})',
        "POST to user-supplied target URL.",
    )
    add(
        "ssrf",
        "u2_ssrf_v_session_get_alias",
        True,
        'import requests as rq\n\ndef ping():\n    loc = request.args.get("loc")\n    return rq.get(loc)',
        "requests imported as rq alias.",
    )
    add(
        "ssrf",
        "u2_ssrf_v_path_join_url",
        True,
        'def asset():\n    base = request.args.get("base")\n    path = request.args.get("path")\n    url = os.path.join(base, path)\n    return requests.get(url)',
        "os.path.join builds URL from user parts.",
    )
    add(
        "ssrf",
        "u2_ssrf_v_urllib_alias",
        True,
        'import urllib.request as urlreq\n\ndef load():\n    link = request.form.get("link")\n    return urlreq.urlopen(link)',
        "urllib.request alias urlopen on user link.",
    )

    add(
        "ssrf",
        "u2_ssrf_s_fixed_healthcheck",
        False,
        'def health():\n    return requests.get("https://status.internal/health").json()',
        "Literal internal health URL.",
    )
    add(
        "ssrf",
        "u2_ssrf_s_allowlist_netloc",
        False,
        'def safe_fetch():\n    raw = request.args.get("raw")\n    host = urlparse(raw).hostname\n    if host not in {"api.example.com", "cdn.example.com"}:\n        raise ValueError("host")\n    return requests.get(raw)',
        "Allowlisted hostname before fetch.",
    )
    add(
        "ssrf",
        "u2_ssrf_s_https_only_scheme",
        False,
        'def safe_https():\n    u = request.args.get("u")\n    if not u.startswith("https://"):\n        raise ValueError("https only")\n    return requests.get(u)',
        "HTTPS-only prefix check before request.",
    )
    add(
        "ssrf",
        "u2_ssrf_s_no_network_call",
        False,
        'def parse_only():\n    raw = request.args.get("raw")\n    return urlparse(raw).path',
        "URL parsed locally, no network.",
    )
    add(
        "ssrf",
        "u2_ssrf_s_literal_urllib",
        False,
        'def static_doc():\n    return urllib.request.urlopen("https://docs.python.org/3/").read()',
        "Literal docs URL only.",
    )
    add(
        "ssrf",
        "u2_ssrf_s_user_logged_static_fetch",
        False,
        'def audit_fetch():\n    who = request.args.get("who")\n    logging.info("fetch by %s", who)\n    return requests.get("https://api.example.com/v1/ping")',
        "User logged; fetch is static API.",
    )
    add(
        "ssrf",
        "u2_ssrf_s_block_private_ip",
        False,
        'def guarded():\n    url = request.args.get("url")\n    host = urlparse(url).hostname\n    if host.startswith("10."):\n        raise ValueError("private")\n    return requests.get(url)',
        "Private 10.x block before fetch.",
    )
    add(
        "ssrf",
        "u2_ssrf_s_fixed_path_append",
        False,
        'def version():\n    base = "https://api.example.com"\n    return requests.get(base + "/version")',
        "Static base with fixed path segment.",
    )
    add(
        "ssrf",
        "u2_ssrf_s_redirect_response_only",
        False,
        'def outbound():\n    dest = request.args.get("dest")\n    return redirect(dest)',
        "Redirect response, not server-side fetch.",
    )
    add(
        "ssrf",
        "u2_ssrf_s_json_return_url",
        False,
        'def echo_url():\n    link = request.args.get("link")\n    return jsonify({"link": link})',
        "URL echoed in JSON, no outbound request.",
    )

    # File upload (20)
    add(
        "file_upload",
        "u2_upload_v_shutil_copy",
        True,
        'def import_file():\n    src = request.files["src"].filename\n    shutil.copy(request.files["src"], "/var/www/html/" + src)',
        "shutil.copy to webroot with user filename.",
    )
    add(
        "file_upload",
        "u2_upload_v_open_write_bytes",
        True,
        'def save_raw():\n    name = request.files["doc"].filename\n    data = request.files["doc"].read()\n    open("/srv/app/static/" + name, "wb").write(data)',
        "open/write to static dir with user name.",
    )
    add(
        "file_upload",
        "u2_upload_v_pathlib_write",
        True,
        'def store_path():\n    fn = request.files["f"].filename\n    Path("/var/www/uploads").joinpath(fn).write_bytes(request.files["f"].read())',
        "Path.joinpath with user filename under web path.",
    )
    add(
        "file_upload",
        "u2_upload_v_double_name_chain",
        True,
        'def chain_save():\n    a = request.files["file"].filename\n    b = a\n    dest = "/var/www/html/" + b\n    request.files["file"].save(dest)',
        "Filename through assignment chain to webroot.",
    )
    add(
        "file_upload",
        "u2_upload_v_no_ext_check",
        True,
        'def quick_save():\n    fname = request.files["upload"].filename\n    request.files["upload"].save(os.path.join("/var/www", fname))',
        "No extension validation before webroot save.",
    )
    add(
        "file_upload",
        "u2_upload_v_public_tmp",
        True,
        'def tmp_public():\n    name = request.files["img"].filename\n    request.files["img"].save("/var/www/html/tmp/" + name)',
        "Save under public tmp with user name.",
    )
    add(
        "file_upload",
        "u2_upload_v_py_extension",
        True,
        'def save_script():\n    fn = request.files["code"].filename\n    if fn.endswith(".py"):\n        request.files["code"].save("/var/www/cgi/" + fn)',
        "Accepts .py uploads into cgi web path.",
    )
    add(
        "file_upload",
        "u2_upload_v_concat_dir",
        True,
        'def folder_put():\n    folder = request.form.get("folder")\n    fn = request.files["f"].filename\n    request.files["f"].save(folder + "/" + fn)',
        "User folder concatenated with filename.",
    )
    add(
        "file_upload",
        "u2_upload_v_join_webroot",
        True,
        'def join_save():\n    fn = request.files["asset"].filename\n    full = os.path.join("/var/www/html/assets", fn)\n    request.files["asset"].save(full)',
        "os.path.join webroot assets with user fn.",
    )
    add(
        "file_upload",
        "u2_upload_v_fstring_dest",
        True,
        'def fsave():\n    fn = request.files["pic"].filename\n    request.files["pic"].save(f"/var/www/html/gallery/{fn}")',
        "f-string destination under html gallery.",
    )

    add(
        "file_upload",
        "u2_upload_s_random_hex_name",
        False,
        'def safe_rand():\n    data = request.files["file"].read()\n    name = secrets.token_hex(16) + ".dat"\n    Path("/data/vault").joinpath(name).write_bytes(data)',
        "Random hex name outside webroot.",
    )
    add(
        "file_upload",
        "u2_upload_s_reject_py_ext",
        False,
        'def reject_exec():\n    fn = request.files["f"].filename\n    if fn.endswith(".py") or fn.endswith(".sh"):\n        raise ValueError("blocked")\n    request.files["f"].save("/data/store/" + fn)',
        "Executable extensions rejected before save.",
    )
    add(
        "file_upload",
        "u2_upload_s_fixed_basename",
        False,
        'def avatar():\n    data = request.files["avatar"].read()\n    open("/data/avatars/current.png", "wb").write(data)',
        "Fixed filename, not user-controlled.",
    )
    add(
        "file_upload",
        "u2_upload_s_whitelist_ext",
        False,
        'def images_only():\n    fn = request.files["img"].filename\n    ext = os.path.splitext(fn)[1].lower()\n    if ext not in {".png", ".jpg"}:\n        raise ValueError("type")\n    request.files["img"].save("/data/images/" + secrets.token_hex(8) + ext)',
        "Extension whitelist + random name off webroot.",
    )
    add(
        "file_upload",
        "u2_upload_s_outside_webroot",
        False,
        'def archive():\n    fn = request.files["doc"].filename\n    request.files["doc"].save("/var/app/archives/" + fn)',
        "Save under non-webroot archives path.",
    )
    add(
        "file_upload",
        "u2_upload_s_no_persist",
        False,
        'def scan_only():\n    content = request.files["f"].read()\n    return hashlib.sha256(content).hexdigest()',
        "File hashed, never written to disk.",
    )
    add(
        "file_upload",
        "u2_upload_s_sanitize_filename",
        False,
        'def clean_name():\n    raw = request.files["f"].filename\n    safe = re.sub(r"[^a-zA-Z0-9._-]", "", raw)\n    request.files["f"].save("/data/files/" + safe)',
        "Filename sanitized to alnum before save off webroot.",
    )
    add(
        "file_upload",
        "u2_upload_s_uuid_subdir",
        False,
        'def uuid_dir():\n    data = request.files["blob"].read()\n    sub = str(uuid.uuid4())\n    Path("/data/blobs/" + sub).write_bytes(data)',
        "UUID subdirectory, no user filename.",
    )
    add(
        "file_upload",
        "u2_upload_s_content_type_check",
        False,
        'def pdf_only():\n    f = request.files["pdf"]\n    if f.content_type != "application/pdf":\n        raise ValueError("pdf")\n    f.save("/data/pdf/" + secrets.token_hex(12) + ".pdf")',
        "Content-type gate + random pdf name.",
    )
    add(
        "file_upload",
        "u2_upload_s_max_size_reject",
        False,
        'def capped():\n    f = request.files["f"]\n    if len(f.read()) > 1000000:\n        raise ValueError("too big")\n    f.seek(0)\n    f.save("/data/capped/" + secrets.token_hex(8) + ".bin")',
        "Size cap + random name in data dir.",
    )

    # IDOR (20)
    add(
        "idor",
        "u2_idor_v_record_id_param",
        True,
        'def fetch_record():\n    rid = request.args.get("record_id")\n    return db.query("SELECT * FROM records WHERE id = ?", rid)',
        "record_id from query without ownership check.",
    )
    add(
        "idor",
        "u2_idor_v_json_user_uuid",
        True,
        'def load_profile():\n    uid = request.json.get("user_uuid")\n    return User.objects.get(pk=uid)',
        "JSON user_uuid fetches arbitrary user.",
    )
    add(
        "idor",
        "u2_idor_v_filter_username",
        True,
        'def find_user():\n    name = request.args.get("username")\n    return User.objects.filter(username=name).first()',
        "Username param selects user without session bind.",
    )
    add(
        "idor",
        "u2_idor_v_delete_invoice",
        True,
        'def delete_invoice():\n    inv = request.form.get("invoice_id")\n    Invoice.objects.filter(id=inv).delete()',
        "Delete by invoice_id without owner guard.",
    )
    add(
        "idor",
        "u2_idor_v_nested_json_owner",
        True,
        'def nested_owner():\n    owner = request.json.get("meta", {}).get("owner_id")\n    return Document.objects.get(id=owner)',
        "Nested JSON owner_id used for lookup.",
    )
    add(
        "idor",
        "u2_idor_v_post_profile_id",
        True,
        'def update_profile():\n    pid = request.form.get("profile_id")\n    bio = request.form.get("bio")\n    Profile.objects.filter(id=pid).update(bio=bio)',
        "profile_id from form drives update.",
    )
    add(
        "idor",
        "u2_idor_v_email_lookup",
        True,
        'def by_email():\n    email = request.args.get("email")\n    return Account.objects.filter(email=email).first()',
        "Email param fetches account without authz.",
    )
    add(
        "idor",
        "u2_idor_v_document_json_id",
        True,
        'def doc_json():\n    doc_id = request.json.get("document_id")\n    return Document.objects.get(id=doc_id)',
        "document_id from JSON body.",
    )
    add(
        "idor",
        "u2_idor_v_account_filter_id",
        True,
        'def account_view():\n    acc = request.args.get("account")\n    return Account.objects.filter(id=acc).first()',
        "account query param filters by id.",
    )
    add(
        "idor",
        "u2_idor_v_quad_hop_lookup",
        True,
        'def quad_lookup():\n    x = request.args.get("x")\n    y = x\n    z = y\n    w = z\n    return Order.objects.get(id=w)',
        "Four-hop chain into ORM get by id.",
    )

    add(
        "idor",
        "u2_idor_s_session_user_only",
        False,
        'def my_orders():\n    uid = session["user_id"]\n    return Order.objects.filter(user_id=uid)',
        "Orders filtered by session user_id.",
    )
    add(
        "idor",
        "u2_idor_s_guard_before_delete",
        False,
        'def safe_delete():\n    doc_id = request.form.get("doc_id")\n    doc = Document.objects.get(id=doc_id)\n    if doc.owner_id != session["user_id"]:\n        raise PermissionError()\n    doc.delete()',
        "Ownership verified before delete.",
    )
    add(
        "idor",
        "u2_idor_s_static_resource",
        False,
        'def public_terms():\n    return Page.objects.get(slug="terms")',
        "Static slug lookup for public page.",
    )
    add(
        "idor",
        "u2_idor_s_no_user_lookup",
        False,
        'def stats():\n    return Metric.objects.aggregate(total=Sum("value"))',
        "Aggregate query, no user-specific lookup.",
    )
    add(
        "idor",
        "u2_idor_s_filter_owner_session",
        False,
        'def my_docs():\n    owner = session["user_id"]\n    return Document.objects.filter(owner_id=owner)',
        "Documents filtered by session owner.",
    )
    add(
        "idor",
        "u2_idor_s_get_with_owner_check",
        False,
        'def safe_get():\n    rid = request.args.get("rid")\n    row = Record.objects.get(id=rid)\n    if row.user_id != g.user.id:\n        raise PermissionError()\n    return row',
        "get then compares row.user_id to g.user.",
    )
    add(
        "idor",
        "u2_idor_s_current_user_profile",
        False,
        'def edit_me():\n    return Profile.objects.get(user_id=current_user.id)',
        "Profile keyed to current_user.id.",
    )
    add(
        "idor",
        "u2_idor_s_admin_role_gate",
        False,
        'def admin_user():\n    uid = request.args.get("uid")\n    if not g.user.is_admin:\n        raise PermissionError()\n    return User.objects.get(id=uid)',
        "Admin role required before user get.",
    )
    add(
        "idor",
        "u2_idor_s_logged_not_queried",
        False,
        'def log_request():\n    target = request.args.get("target")\n    logging.info("target=%s", target)\n    return {"status": "ok"}',
        "target logged, no ORM lookup.",
    )
    add(
        "idor",
        "u2_idor_s_list_public",
        False,
        'def list_public():\n    return Article.objects.filter(is_public=True)',
        "Public articles only, no user id param.",
    )
