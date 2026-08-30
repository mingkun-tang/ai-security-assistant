"""Holdout #3 SSRF, file_upload, and IDOR cases."""

from __future__ import annotations

from case_helpers import add


def register(cases: list) -> None:
    # --- SSRF vulnerable (15) ---
    add(
        cases,
        "ssrf",
        "u3_ssrf_v_requests_request_method",
        True,
        '''
        def proxy_get():
            endpoint = request.args.get("endpoint")
            return requests.request("GET", endpoint).text
        ''',
        "requests.request GET with user-controlled URL.",
    )
    add(
        cases,
        "ssrf",
        "u3_ssrf_v_httpx_post_target",
        True,
        '''
        import httpx

        def forward_hook():
            hook = request.json.get("hook")
            return httpx.post(hook, json={"ok": True}).text
        ''',
        "httpx.post to user JSON hook URL.",
    )
    add(
        cases,
        "ssrf",
        "u3_ssrf_v_aiohttp_get_remote",
        True,
        '''
        import aiohttp

        def pull_remote():
            remote = request.args.get("remote")
            return aiohttp.ClientSession().get(remote)
        ''',
        "aiohttp ClientSession.get on user remote URL.",
    )
    add(
        cases,
        "ssrf",
        "u3_ssrf_v_urlopen_direct",
        True,
        '''
        def fetch_page():
            page = request.form.get("page")
            return urllib.request.urlopen(page).read()
        ''',
        "urllib.request.urlopen on form-supplied page URL.",
    )
    add(
        cases,
        "ssrf",
        "u3_ssrf_v_session_instance_get",
        True,
        '''
        def session_probe():
            addr = request.args.get("addr")
            client = requests.Session()
            return client.get(addr).content
        ''',
        "requests.Session().get with user addr.",
    )
    add(
        cases,
        "ssrf",
        "u3_ssrf_v_requests_as_req",
        True,
        '''
        import requests as req

        def mirror_url():
            src = request.args.get("src")
            return req.get(src)
        ''',
        "requests imported as req then get user src.",
    )
    add(
        cases,
        "ssrf",
        "u3_ssrf_v_fstring_host_path",
        True,
        '''
        def status_of():
            host = request.args.get("host")
            return requests.get(f"https://{host}/v1/ready")
        ''',
        "f-string embeds user host into request URL.",
    )
    add(
        cases,
        "ssrf",
        "u3_ssrf_v_scheme_host_concat",
        True,
        '''
        def build_fetch():
            proto = request.args.get("proto")
            node = request.args.get("node")
            return requests.get(proto + "://" + node + "/info")
        ''',
        "Concatenated scheme and host form outbound URL.",
    )
    add(
        cases,
        "ssrf",
        "u3_ssrf_v_triple_hop_url",
        True,
        '''
        def hop_fetch():
            a = request.args.get("a")
            b = a
            c = b
            return requests.get(c).text
        ''',
        "Multi-hop assignment of user URL into requests.get.",
    )
    add(
        cases,
        "ssrf",
        "u3_ssrf_v_json_webhook_url",
        True,
        '''
        def fire_webhook():
            webhook = request.json.get("webhook_url")
            return urllib.request.urlopen(webhook).read()
        ''',
        "JSON webhook_url opened via urllib.",
    )
    add(
        cases,
        "ssrf",
        "u3_ssrf_v_form_target_post",
        True,
        '''
        def submit_remote():
            target = request.form.get("target")
            return requests.post(target, data={"event": "ping"})
        ''',
        "Form target drives server-side POST.",
    )
    add(
        cases,
        "ssrf",
        "u3_ssrf_v_path_join_then_get",
        True,
        '''
        def join_fetch():
            root = request.args.get("root")
            leaf = request.args.get("leaf")
            built = os.path.join(root, leaf)
            return requests.get(built)
        ''',
        "os.path.join builds URL from user parts then GET.",
    )
    add(
        cases,
        "ssrf",
        "u3_ssrf_v_httpx_client_get",
        True,
        '''
        from httpx import Client

        def client_get():
            loc = request.args.get("loc")
            with Client() as client:
                return client.get(loc).text
        ''',
        "httpx Client().get on user loc.",
    )
    add(
        cases,
        "ssrf",
        "u3_ssrf_v_weak_nested_if_fetch",
        True,
        '''
        def maybe_fetch():
            url = request.args.get("url")
            if url:
                if "://" in url:
                    return requests.get(url).content
            return b""
        ''',
        "Nested if only checks presence/scheme marker, still fetches user URL.",
    )
    add(
        cases,
        "ssrf",
        "u3_ssrf_v_urllib_alias_open",
        True,
        '''
        import urllib.request as ureq

        def open_alias():
            link = request.form.get("link")
            return ureq.urlopen(link).read()
        ''',
        "urllib.request aliased urlopen on user link.",
    )

    # --- SSRF safe (15) ---
    add(
        cases,
        "ssrf",
        "u3_ssrf_s_fixed_health_url",
        False,
        '''
        def health_probe():
            return requests.get("https://monitor.internal/healthz").json()
        ''',
        "Fixed literal health URL only.",
    )
    add(
        cases,
        "ssrf",
        "u3_ssrf_s_hostname_allowlist_abort",
        False,
        '''
        def allowlisted_fetch():
            raw = request.args.get("raw")
            host = urlparse(raw).hostname
            if host not in {"hooks.partner.com", "cdn.partner.com"}:
                raise ValueError("denied")
            return requests.get(raw)
        ''',
        "Hostname allowlist with raise before fetch.",
    )
    add(
        cases,
        "ssrf",
        "u3_ssrf_s_https_startswith_guard",
        False,
        '''
        def https_only_pull():
            u = request.args.get("u")
            if not u.startswith("https://"):
                abort(400)
            return requests.get(u)
        ''',
        "https:// startswith guard then fetch.",
    )
    add(
        cases,
        "ssrf",
        "u3_ssrf_s_block_10_prefix",
        False,
        '''
        def no_private_ten():
            url = request.args.get("url")
            host = urlparse(url).hostname or ""
            if host.startswith("10."):
                raise ValueError("private")
            return requests.get(url)
        ''',
        "Blocks private 10. hostname prefix before fetch.",
    )
    add(
        cases,
        "ssrf",
        "u3_ssrf_s_urlparse_only",
        False,
        '''
        def inspect_url():
            raw = request.args.get("raw")
            parsed = urlparse(raw)
            return {"scheme": parsed.scheme, "path": parsed.path}
        ''',
        "urlparse only; no network call.",
    )
    add(
        cases,
        "ssrf",
        "u3_ssrf_s_user_logged_static_get",
        False,
        '''
        def audit_static():
            actor = request.args.get("actor")
            logging.info("actor=%s", actor)
            return requests.get("https://api.partner.com/v2/ping")
        ''',
        "User value logged; fetch uses static URL.",
    )
    add(
        cases,
        "ssrf",
        "u3_ssrf_s_redirect_dest_only",
        False,
        '''
        def bounce_out():
            dest = request.args.get("dest")
            return redirect(dest)
        ''',
        "redirect(dest) only — client redirect, not SSRF.",
    )
    add(
        cases,
        "ssrf",
        "u3_ssrf_s_jsonify_link_echo",
        False,
        '''
        def echo_link():
            link = request.args.get("link")
            return jsonify({"link": link})
        ''',
        "JSON echo of link; no outbound request.",
    )
    add(
        cases,
        "ssrf",
        "u3_ssrf_s_fixed_base_path",
        False,
        '''
        def release_info():
            base = "https://releases.example.com"
            return requests.get(base + "/latest.json")
        ''',
        "Fixed base + fixed path concat; no user input.",
    )
    add(
        cases,
        "ssrf",
        "u3_ssrf_s_literal_urllib_docs",
        False,
        '''
        def load_changelog():
            return urllib.request.urlopen("https://example.com/changelog.txt").read()
        ''',
        "Literal urllib URL only.",
    )
    add(
        cases,
        "ssrf",
        "u3_ssrf_s_parsed_hostname_not_in",
        False,
        '''
        def deny_unknown_host():
            raw = request.args.get("raw")
            host = urlparse(raw).hostname
            allowed = {"api.trusted.com"}
            if host not in allowed:
                raise PermissionError("host")
            return requests.get(raw)
        ''',
        "Allowlist via parsed.hostname not in check.",
    )
    add(
        cases,
        "ssrf",
        "u3_ssrf_s_scheme_must_be_https",
        False,
        '''
        def require_https_scheme():
            u = request.args.get("u")
            if urlparse(u).scheme != "https":
                abort(400)
            return requests.get(u)
        ''',
        "scheme != https aborts before fetch.",
    )
    add(
        cases,
        "ssrf",
        "u3_ssrf_s_host_in_allowlist_set",
        False,
        '''
        def set_allow_fetch():
            raw = request.args.get("raw")
            host = urlparse(raw).hostname
            allow = {"img.cdn.com", "static.cdn.com"}
            if host in allow:
                return requests.get(raw)
            raise ValueError("blocked")
        ''',
        "Host must be in allowlist set before GET.",
    )
    add(
        cases,
        "ssrf",
        "u3_ssrf_s_return_path_only",
        False,
        '''
        def path_of():
            raw = request.args.get("raw")
            return urlparse(raw).path
        ''',
        "No network — returns parsed path only.",
    )
    add(
        cases,
        "ssrf",
        "u3_ssrf_s_static_metrics_url",
        False,
        '''
        def scrape_metrics():
            return requests.get("https://metrics.internal/prometheus").text
        ''',
        "Static metrics URL with no user control.",
    )

    # --- File upload vulnerable (15) ---
    add(
        cases,
        "file_upload",
        "u3_upload_v_save_webroot_filename",
        True,
        '''
        def publish_file():
            name = request.files["upload"].filename
            request.files["upload"].save("/var/www/html/" + name)
        ''',
        ".save to webroot using user filename.",
    )
    add(
        cases,
        "file_upload",
        "u3_upload_v_shutil_copy_www",
        True,
        '''
        def copy_into_www():
            name = request.files["blob"].filename
            shutil.copy(request.files["blob"], "/var/www/" + name)
        ''',
        "shutil.copy into /var/www with user filename.",
    )
    add(
        cases,
        "file_upload",
        "u3_upload_v_open_write_webroot",
        True,
        '''
        def dump_static():
            name = request.files["doc"].filename
            data = request.files["doc"].read()
            open("/srv/www/static/" + name, "wb").write(data)
        ''',
        "open().write under webroot with user name.",
    )
    add(
        cases,
        "file_upload",
        "u3_upload_v_path_write_bytes_www",
        True,
        '''
        def path_drop():
            fn = request.files["f"].filename
            Path("/var/www/html/media/" + fn).write_bytes(request.files["f"].read())
        ''',
        "Path.write_bytes under html media with user fn.",
    )
    add(
        cases,
        "file_upload",
        "u3_upload_v_joinpath_write",
        True,
        '''
        def join_write():
            fn = request.files["asset"].filename
            Path("/var/www/html/assets").joinpath(fn).write_bytes(request.files["asset"].read())
        ''',
        "Path.joinpath then write under webroot.",
    )
    add(
        cases,
        "file_upload",
        "u3_upload_v_double_alias_save",
        True,
        '''
        def alias_chain_save():
            first = request.files["file"].filename
            second = first
            dest = "/var/www/html/inbox/" + second
            request.files["file"].save(dest)
        ''',
        "Double alias filename chain saved under webroot.",
    )
    add(
        cases,
        "file_upload",
        "u3_upload_v_fstring_gallery",
        True,
        '''
        def gallery_put():
            fn = request.files["pic"].filename
            request.files["pic"].save(f"/var/www/html/gallery/{fn}")
        ''',
        "f-string gallery path under html with user fn.",
    )
    add(
        cases,
        "file_upload",
        "u3_upload_v_os_join_webroot",
        True,
        '''
        def join_web_save():
            fn = request.files["asset"].filename
            path = os.path.join("/var/www/html/files", fn)
            request.files["asset"].save(path)
        ''',
        "os.path.join webroot then save user filename.",
    )
    add(
        cases,
        "file_upload",
        "u3_upload_v_form_folder_concat",
        True,
        '''
        def folder_upload():
            folder = request.form.get("folder")
            fn = request.files["f"].filename
            request.files["f"].save(folder + "/" + fn)
        ''',
        "Form folder concatenated with user filename.",
    )
    add(
        cases,
        "file_upload",
        "u3_upload_v_public_tmp_html",
        True,
        '''
        def tmp_under_html():
            name = request.files["img"].filename
            request.files["img"].save("/var/www/html/tmp/" + name)
        ''',
        "Public tmp under html with user name.",
    )
    add(
        cases,
        "file_upload",
        "u3_upload_v_py_to_cgi_www",
        True,
        '''
        def accept_py_cgi():
            fn = request.files["code"].filename
            if fn.endswith(".py"):
                request.files["code"].save("/var/www/cgi-bin/" + fn)
        ''',
        ".py extension accepted into cgi web path.",
    )
    add(
        cases,
        "file_upload",
        "u3_upload_v_shutil_copyfile_www",
        True,
        '''
        def copyfile_www():
            name = request.files["src"].filename
            tmp = "/tmp/" + name
            request.files["src"].save(tmp)
            shutil.copyfile(tmp, "/var/www/html/" + name)
        ''',
        "shutil.copyfile into webroot with user name.",
    )
    add(
        cases,
        "file_upload",
        "u3_upload_v_write_text_pathlib",
        True,
        '''
        def text_to_www():
            fn = request.files["note"].filename
            text = request.files["note"].read().decode("utf-8", errors="ignore")
            Path("/var/www/html/notes/" + fn).write_text(text)
        ''',
        "Path.write_text under webroot notes.",
    )
    add(
        cases,
        "file_upload",
        "u3_upload_v_multihop_dest_save",
        True,
        '''
        def hop_dest_save():
            a = request.files["file"].filename
            b = a
            dest = "/var/www/html/drop/" + b
            request.files["file"].save(dest)
        ''',
        "Multi-hop dest then save under webroot.",
    )
    add(
        cases,
        "file_upload",
        "u3_upload_v_no_ext_join_www",
        True,
        '''
        def unchecked_join():
            fname = request.files["upload"].filename
            request.files["upload"].save(os.path.join("/var/www/html", fname))
        ''',
        "No extension check; webroot join with user name.",
    )

    # --- File upload safe (15) ---
    add(
        cases,
        "file_upload",
        "u3_upload_s_token_hex_off_webroot",
        False,
        '''
        def vault_store():
            data = request.files["file"].read()
            name = secrets.token_hex(16) + ".bin"
            Path("/data/vault").joinpath(name).write_bytes(data)
        ''',
        "secrets.token_hex name stored off webroot.",
    )
    add(
        cases,
        "file_upload",
        "u3_upload_s_reject_py_sh_data",
        False,
        '''
        def reject_scripts():
            fn = request.files["f"].filename
            if fn.endswith(".py") or fn.endswith(".sh"):
                raise ValueError("blocked")
            request.files["f"].save("/data/inbox/" + secrets.token_hex(12) + ".bin")
        ''',
        "Reject .py/.sh then save random name under data dir.",
    )
    add(
        cases,
        "file_upload",
        "u3_upload_s_fixed_basename",
        False,
        '''
        def fixed_avatar():
            data = request.files["avatar"].read()
            open("/data/avatars/profile.png", "wb").write(data)
        ''',
        "Fixed basename destination, not user-controlled.",
    )
    add(
        cases,
        "file_upload",
        "u3_upload_s_whitelist_png_jpg_random",
        False,
        '''
        def images_whitelist():
            fn = request.files["img"].filename
            ext = os.path.splitext(fn)[1].lower()
            if ext not in {".png", ".jpg"}:
                raise ValueError("type")
            request.files["img"].save("/data/images/" + secrets.token_hex(8) + ext)
        ''',
        "Whitelist png/jpg plus random name off webroot.",
    )
    add(
        cases,
        "file_upload",
        "u3_upload_s_archives_fixed_name",
        False,
        '''
        def archive_store():
            data = request.files["doc"].read()
            open("/data/store/latest.archive", "wb").write(data)
        ''',
        "Outside webroot with fixed destination name.",
    )
    add(
        cases,
        "file_upload",
        "u3_upload_s_hash_only_no_persist",
        False,
        '''
        def hash_upload():
            content = request.files["f"].read()
            return hashlib.sha256(content).hexdigest()
        ''',
        "Hash only; no file persist.",
    )
    add(
        cases,
        "file_upload",
        "u3_upload_s_uuid_subdir_no_user_name",
        False,
        '''
        def uuid_blob():
            data = request.files["blob"].read()
            sub = str(uuid.uuid4())
            Path("/data/blobs/" + sub + "/payload.bin").write_bytes(data)
        ''',
        "UUID subdir write with fixed payload name.",
    )
    add(
        cases,
        "file_upload",
        "u3_upload_s_content_type_pdf_random",
        False,
        '''
        def pdf_gate():
            f = request.files["pdf"]
            if f.content_type != "application/pdf":
                raise ValueError("pdf")
            f.save("/data/pdf/" + secrets.token_hex(12) + ".pdf")
        ''',
        "Content-type pdf gate + random destination name.",
    )
    add(
        cases,
        "file_upload",
        "u3_upload_s_max_size_random",
        False,
        '''
        def size_capped():
            f = request.files["f"]
            raw = f.read()
            if len(raw) > 500000:
                raise ValueError("too big")
            Path("/data/capped/" + secrets.token_hex(8) + ".bin").write_bytes(raw)
        ''',
        "Max size check + random name under data.",
    )
    add(
        cases,
        "file_upload",
        "u3_upload_s_sanitize_then_hex",
        False,
        '''
        def sanitized_hex_save():
            raw = request.files["f"].filename
            cleaned = re.sub(r"[^a-zA-Z0-9._-]", "", raw)
            if not cleaned:
                raise ValueError("name")
            request.files["f"].save("/data/files/" + secrets.token_hex(10) + ".dat")
        ''',
        "Sanitize check then random hex name in data dir.",
    )
    add(
        cases,
        "file_upload",
        "u3_upload_s_path_token_name",
        False,
        '''
        def path_token_write():
            data = request.files["f"].read()
            Path("/data/objects/" + secrets.token_hex(16)).write_bytes(data)
        ''',
        "Path write with token_hex name off webroot.",
    )
    add(
        cases,
        "file_upload",
        "u3_upload_s_private_token_hex",
        False,
        '''
        def private_store():
            f = request.files["file"]
            f.save("/var/app/private/" + secrets.token_hex(16) + ".bin")
        ''',
        "Save to /var/app/private with token_hex name.",
    )
    add(
        cases,
        "file_upload",
        "u3_upload_s_allow_image_jpg_random",
        False,
        '''
        def allow_image_jpg():
            fn = request.files["img"].filename
            if not fn.lower().endswith(".jpg"):
                raise ValueError("jpg only")
            request.files["img"].save("/data/photos/" + secrets.token_hex(8) + ".jpg")
        ''',
        "endswith jpg gate then random name under /data.",
    )
    add(
        cases,
        "file_upload",
        "u3_upload_s_read_len_only",
        False,
        '''
        def measure_only():
            data = request.files["f"].read()
            return len(data)
        ''',
        "No upload save — only read bytes and return length.",
    )
    add(
        cases,
        "file_upload",
        "u3_upload_s_shutil_copy_vault_random",
        False,
        '''
        def copy_to_vault():
            src = request.files["src"]
            tmp = "/tmp/" + secrets.token_hex(8)
            src.save(tmp)
            dest = "/data/vault/" + secrets.token_hex(16) + ".bin"
            shutil.copy(tmp, dest)
        ''',
        "shutil.copy to /data/vault with secrets destination name.",
    )

    # --- IDOR vulnerable (15) ---
    add(
        cases,
        "idor",
        "u3_idor_v_objects_get_request_id",
        True,
        '''
        def show_order():
            oid = request.args.get("order_id")
            return Order.objects.get(id=oid)
        ''',
        "objects.get(id=) from request without ownership check.",
    )
    add(
        cases,
        "idor",
        "u3_idor_v_filter_user_id",
        True,
        '''
        def posts_for_user():
            uid = request.args.get("user_id")
            return Post.objects.filter(user_id=uid)
        ''',
        "filter(user_id=) from query param.",
    )
    add(
        cases,
        "idor",
        "u3_idor_v_filter_username",
        True,
        '''
        def lookup_by_name():
            name = request.args.get("username")
            return Member.objects.filter(username=name).first()
        ''',
        "filter(username=) without session bind.",
    )
    add(
        cases,
        "idor",
        "u3_idor_v_filter_email",
        True,
        '''
        def find_by_email():
            email = request.args.get("email")
            return Customer.objects.filter(email=email).first()
        ''',
        "filter(email=) fetches arbitrary customer.",
    )
    add(
        cases,
        "idor",
        "u3_idor_v_db_query_key",
        True,
        '''
        def load_row():
            key = request.args.get("key")
            return db.query("SELECT * FROM items WHERE key = ?", key)
        ''',
        "db.query keyed by user-supplied key.",
    )
    add(
        cases,
        "idor",
        "u3_idor_v_json_document_id",
        True,
        '''
        def fetch_document():
            doc_id = request.json.get("document_id")
            return Document.objects.get(id=doc_id)
        ''',
        "JSON body document_id drives ORM get.",
    )
    add(
        cases,
        "idor",
        "u3_idor_v_nested_meta_owner",
        True,
        '''
        def nested_meta_owner():
            owner = request.json.get("meta", {}).get("owner_id")
            return Workspace.objects.get(id=owner)
        ''',
        "Nested json meta.owner_id used as identity.",
    )
    add(
        cases,
        "idor",
        "u3_idor_v_form_invoice_delete",
        True,
        '''
        def wipe_invoice():
            inv = request.form.get("invoice_id")
            Invoice.objects.filter(id=inv).delete()
        ''',
        "Form invoice_id delete filter without owner check.",
    )
    add(
        cases,
        "idor",
        "u3_idor_v_ticket_key_args",
        True,
        '''
        def open_ticket():
            ticket_key = request.args.get("ticket_key")
            return Ticket.objects.get(key=ticket_key)
        ''',
        "Path-like ticket_key from args selects ticket.",
    )
    add(
        cases,
        "idor",
        "u3_idor_v_uuid_from_args",
        True,
        '''
        def by_uuid():
            uid = request.args.get("uuid")
            return Resource.objects.get(uuid=uid)
        ''',
        "uuid from args used in objects.get.",
    )
    add(
        cases,
        "idor",
        "u3_idor_v_multihop_into_get",
        True,
        '''
        def hop_get():
            x = request.args.get("x")
            y = x
            z = y
            return Report.objects.get(id=z)
        ''',
        "Multi-hop assignment into objects.get.",
    )
    add(
        cases,
        "idor",
        "u3_idor_v_account_filter_id",
        True,
        '''
        def view_account():
            acc = request.args.get("account_id")
            return Account.objects.filter(id=acc).first()
        ''',
        "Account filter by user-supplied id.",
    )
    add(
        cases,
        "idor",
        "u3_idor_v_profile_id_update",
        True,
        '''
        def patch_profile():
            pid = request.form.get("profile_id")
            bio = request.form.get("bio")
            Profile.objects.filter(id=pid).update(bio=bio)
        ''',
        "profile_id from form drives update.",
    )
    add(
        cases,
        "idor",
        "u3_idor_v_filter_username_identity",
        True,
        '''
        def identity_by_username():
            handle = request.args.get("handle")
            return User.objects.filter(username=handle).first()
        ''',
        "User-supplied handle used as username identity filter.",
    )
    add(
        cases,
        "idor",
        "u3_idor_v_objects_get_pk_json",
        True,
        '''
        def pk_from_json():
            pk = request.json.get("pk")
            return Widget.objects.get(pk=pk)
        ''',
        "objects.get(pk=) from JSON body.",
    )

    # --- IDOR safe (15) ---
    add(
        cases,
        "idor",
        "u3_idor_s_session_user_id_filter",
        False,
        '''
        class Workspace:
            objects = None

        def list_mine():
            actor = session.get("uid")
            return Workspace.objects.filter(owner_id=actor).order_by("-created_at")
        ''',
        "Session-scoped owner filter with no client-supplied identity key.",
    )
    add(
        cases,
        "idor",
        "u3_idor_s_ownership_raise_before_return",
        False,
        '''
        def guarded_record():
            rid = request.args.get("rid")
            row = Record.objects.get(id=rid)
            if row.owner_id != session["user_id"]:
                raise PermissionError()
            return row
        ''',
        "Ownership check before return (raise).",
    )
    add(
        cases,
        "idor",
        "u3_idor_s_g_user_ownership",
        False,
        '''
        def g_user_doc():
            did = request.args.get("did")
            doc = Document.objects.get(id=did)
            if doc.owner_id != g.user.id:
                raise PermissionError()
            return doc
        ''',
        "g.user.id ownership compare before return.",
    )
    add(
        cases,
        "idor",
        "u3_idor_s_admin_is_admin_gate",
        False,
        '''
        def admin_fetch_user():
            uid = request.args.get("uid")
            if not g.user.is_admin:
                raise PermissionError()
            return User.objects.get(id=uid)
        ''',
        "Admin is_admin gate then get.",
    )
    add(
        cases,
        "idor",
        "u3_idor_s_current_user_profile",
        False,
        '''
        def my_profile():
            return Profile.objects.get(user_id=current_user.id)
        ''',
        "Profile keyed to current_user.id.",
    )
    add(
        cases,
        "idor",
        "u3_idor_s_static_slug_terms",
        False,
        '''
        def terms_page():
            return Page.objects.get(slug="terms")
        ''',
        "Static slug terms lookup.",
    )
    add(
        cases,
        "idor",
        "u3_idor_s_public_filter",
        False,
        '''
        def public_posts():
            return Article.objects.filter(is_public=True)
        ''',
        "Public is_public=True filter only.",
    )
    add(
        cases,
        "idor",
        "u3_idor_s_aggregate_no_user_key",
        False,
        '''
        def totals():
            return Metric.objects.aggregate(total=Sum("value"))
        ''',
        "Aggregate with no user key.",
    )
    add(
        cases,
        "idor",
        "u3_idor_s_logged_target_no_query",
        False,
        '''
        def log_target():
            target = request.args.get("target")
            logging.info("target=%s", target)
            return {"ok": True}
        ''',
        "Logged target; no ORM query.",
    )
    add(
        cases,
        "idor",
        "u3_idor_s_filter_owner_session",
        False,
        '''
        def session_owned_docs():
            return Document.objects.filter(owner_id=session["user_id"])
        ''',
        "filter owner_id=session user.",
    )
    add(
        cases,
        "idor",
        "u3_idor_s_get_then_owner_raise",
        False,
        '''
        def get_then_check():
            rid = request.args.get("rid")
            row = Note.objects.get(id=rid)
            if row.owner_id != session["user_id"]:
                raise PermissionError()
            return row
        ''',
        "get then owner_id != session raise.",
    )
    add(
        cases,
        "idor",
        "u3_idor_s_is_staff_gate",
        False,
        '''
        def staff_user_view():
            uid = request.args.get("uid")
            if not g.user.is_staff:
                raise PermissionError()
            return User.objects.get(id=uid)
        ''',
        "role is_staff gate before get.",
    )
    add(
        cases,
        "idor",
        "u3_idor_s_return_constant",
        False,
        '''
        def ping_status():
            ignored = request.args.get("id")
            return {"status": "ok"}
        ''',
        "No user lookup — return constant.",
    )
    add(
        cases,
        "idor",
        "u3_idor_s_filter_owner_g_user",
        False,
        '''
        def g_owned_documents():
            return Document.objects.filter(owner_id=g.user.id)
        ''',
        "Document.objects.filter(owner_id=g.user.id).",
    )
    add(
        cases,
        "idor",
        "u3_idor_s_safe_delete_ownership",
        False,
        '''
        def safe_delete_doc():
            doc_id = request.form.get("doc_id")
            doc = Document.objects.get(id=doc_id)
            if doc.owner_id != session["user_id"]:
                raise PermissionError()
            doc.delete()
        ''',
        "Safe delete with ownership check.",
    )
