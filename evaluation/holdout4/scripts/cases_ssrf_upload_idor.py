"""Holdout #4 SSRF, file_upload, and IDOR cases."""

from __future__ import annotations

from case_helpers import add


def register(cases: list) -> None:
    # --- SSRF vulnerable (10) ---
    add(
        cases,
        "ssrf",
        "u4_ssrf_v_requests_get_callback",
        True,
        '''
        def pull_callback():
            callback = request.args.get("callback")
            return requests.get(callback).text
        ''',
        "requests.get with user-controlled callback URL.",
    )
    add(
        cases,
        "ssrf",
        "u4_ssrf_v_requests_post_notify",
        True,
        '''
        def notify_remote():
            notify = request.args.get("notify")
            return requests.post(notify, json={"event": "ready"})
        ''',
        "requests.post to user-supplied notify URL.",
    )
    add(
        cases,
        "ssrf",
        "u4_ssrf_v_httpx_get_feed",
        True,
        '''
        import httpx

        def mirror_feed():
            feed = request.args.get("feed")
            return httpx.get(feed).text
        ''',
        "httpx.get on user feed URL.",
    )
    add(
        cases,
        "ssrf",
        "u4_ssrf_v_urlopen_resource",
        True,
        '''
        def load_resource():
            resource = request.form.get("resource")
            return urllib.request.urlopen(resource).read()
        ''',
        "urllib.request.urlopen on form resource URL.",
    )
    add(
        cases,
        "ssrf",
        "u4_ssrf_v_session_get_probe",
        True,
        '''
        def probe_peer():
            peer = request.args.get("peer")
            sess = requests.Session()
            return sess.get(peer).content
        ''',
        "requests.Session().get with user peer URL.",
    )
    add(
        cases,
        "ssrf",
        "u4_ssrf_v_fstring_service_url",
        True,
        '''
        def hit_service():
            service = request.args.get("service")
            return requests.get(f"https://{service}/status")
        ''',
        "f-string embeds user service host into GET URL.",
    )
    add(
        cases,
        "ssrf",
        "u4_ssrf_v_concat_base_path",
        True,
        '''
        def concat_fetch():
            base = request.args.get("base")
            return requests.get(base + "/v1/check")
        ''',
        "Concatenated user base URL then GET.",
    )
    add(
        cases,
        "ssrf",
        "u4_ssrf_v_json_callback_hook",
        True,
        '''
        def fire_hook():
            hook = request.json.get("callback_hook")
            return urllib.request.urlopen(hook).read()
        ''',
        "JSON callback_hook opened via urllib.",
    )
    add(
        cases,
        "ssrf",
        "u4_ssrf_v_form_egress_target",
        True,
        '''
        def egress_post():
            egress = request.form.get("egress")
            return requests.post(egress, data={"ping": "1"})
        ''',
        "Form egress drives server-side POST.",
    )
    add(
        cases,
        "ssrf",
        "u4_ssrf_v_alias_req_get",
        True,
        '''
        import requests as http_client

        def alias_pull():
            src = request.args.get("src")
            mid = src
            return http_client.get(mid)
        ''',
        "Aliased requests import plus multi-hop into get.",
    )

    # --- SSRF safe (10) ---
    add(
        cases,
        "ssrf",
        "u4_ssrf_s_literal_uptime_url",
        False,
        '''
        def uptime_check():
            return requests.get("https://status.partner.net/uptime").json()
        ''',
        "Literal fixed uptime URL only.",
    )
    add(
        cases,
        "ssrf",
        "u4_ssrf_s_hostname_notin_abort",
        False,
        '''
        def partner_only_fetch():
            raw = request.args.get("raw")
            host = urlparse(raw).hostname
            if host not in {"hooks.acme.io", "events.acme.io"}:
                abort(403)
            return requests.get(raw)
        ''',
        "Hostname allowlist via NotIn then abort before fetch.",
    )
    add(
        cases,
        "ssrf",
        "u4_ssrf_s_https_startswith_raise",
        False,
        '''
        def https_prefix_gate():
            link = request.args.get("link")
            if not link.startswith("https://"):
                raise ValueError("https required")
            return requests.get(link)
        ''',
        "https:// startswith guard with raise before fetch.",
    )
    add(
        cases,
        "ssrf",
        "u4_ssrf_s_parse_components_only",
        False,
        '''
        def describe_url():
            raw = request.args.get("raw")
            parsed = urlparse(raw)
            return {"netloc": parsed.netloc, "path": parsed.path}
        ''',
        "urlparse only; no outbound network call.",
    )
    add(
        cases,
        "ssrf",
        "u4_ssrf_s_client_redirect_only",
        False,
        '''
        def bounce_client():
            next_url = request.args.get("next")
            return redirect(next_url)
        ''',
        "Client redirect only — not server-side SSRF.",
    )
    add(
        cases,
        "ssrf",
        "u4_ssrf_s_jsonify_url_echo",
        False,
        '''
        def echo_url():
            url = request.args.get("url")
            return jsonify({"url": url})
        ''',
        "JSON echo of URL; no outbound request.",
    )
    add(
        cases,
        "ssrf",
        "u4_ssrf_s_log_user_static_get",
        False,
        '''
        def audited_static_pull():
            who = request.args.get("who")
            logging.info("who=%s", who)
            return requests.get("https://cdn.partner.net/v1/ping")
        ''',
        "User value logged; fetch uses static URL.",
    )
    add(
        cases,
        "ssrf",
        "u4_ssrf_s_fixed_release_concat",
        False,
        '''
        def release_manifest():
            root = "https://releases.partner.net"
            return requests.get(root + "/manifest.json")
        ''',
        "Fixed base + fixed path concat; no user input.",
    )
    add(
        cases,
        "ssrf",
        "u4_ssrf_s_private_prefix_bound_host",
        False,
        '''
        def block_rfc1918_fetch():
            url = request.args.get("url")
            host = urlparse(url).hostname
            if host.startswith("192.168."):
                raise ValueError("private")
            return requests.get(url)
        ''',
        "Bound hostname private-prefix block before fetch.",
    )
    add(
        cases,
        "ssrf",
        "u4_ssrf_s_scheme_bound_https_gate",
        False,
        '''
        def require_bound_https():
            u = request.args.get("u")
            parsed = urlparse(u)
            if parsed.scheme != "https":
                abort(400)
            return requests.get(u)
        ''',
        "Bound parsed.scheme NotEq https aborts before fetch.",
    )

    # --- File upload vulnerable (10) ---
    add(
        cases,
        "file_upload",
        "u4_upload_v_save_html_filename",
        True,
        '''
        def publish_upload():
            name = request.files["upload"].filename
            request.files["upload"].save("/var/www/html/" + name)
        ''',
        ".save under webroot using user filename.",
    )
    add(
        cases,
        "file_upload",
        "u4_upload_v_shutil_copy_wwwroot",
        True,
        '''
        def mirror_into_www():
            name = request.files["blob"].filename
            shutil.copy(request.files["blob"], "/var/www/" + name)
        ''',
        "shutil.copy into /var/www with user filename.",
    )
    add(
        cases,
        "file_upload",
        "u4_upload_v_open_write_static",
        True,
        '''
        def write_static_asset():
            name = request.files["doc"].filename
            data = request.files["doc"].read()
            open("/srv/www/static/" + name, "wb").write(data)
        ''',
        "open().write under webroot with user name.",
    )
    add(
        cases,
        "file_upload",
        "u4_upload_v_path_write_bytes_media",
        True,
        '''
        def drop_media():
            fn = request.files["f"].filename
            Path("/var/www/html/media/" + fn).write_bytes(request.files["f"].read())
        ''',
        "Path.write_bytes under html media with user fn.",
    )
    add(
        cases,
        "file_upload",
        "u4_upload_v_fstring_uploads_path",
        True,
        '''
        def gallery_store():
            fn = request.files["pic"].filename
            request.files["pic"].save(f"/var/www/html/uploads/{fn}")
        ''',
        "f-string upload path under html with user fn.",
    )
    add(
        cases,
        "file_upload",
        "u4_upload_v_os_join_html_files",
        True,
        '''
        def join_html_save():
            fn = request.files["asset"].filename
            path = os.path.join("/var/www/html/files", fn)
            request.files["asset"].save(path)
        ''',
        "os.path.join webroot then save user filename.",
    )
    add(
        cases,
        "file_upload",
        "u4_upload_v_double_alias_web_save",
        True,
        '''
        def alias_filename_save():
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
        "u4_upload_v_concat_dest_folder",
        True,
        '''
        def folder_concat_save():
            folder = request.form.get("folder")
            fn = request.files["f"].filename
            request.files["f"].save(folder + "/" + fn)
        ''',
        "Form folder concatenated with user filename.",
    )
    add(
        cases,
        "file_upload",
        "u4_upload_v_public_html_drop",
        True,
        '''
        def public_html_drop():
            name = request.files["img"].filename
            request.files["img"].save("/var/www/html/public/" + name)
        ''',
        "Public html path with user-controlled name.",
    )
    add(
        cases,
        "file_upload",
        "u4_upload_v_copyfile_into_html",
        True,
        '''
        def copyfile_html():
            name = request.files["src"].filename
            tmp = "/tmp/" + name
            request.files["src"].save(tmp)
            shutil.copyfile(tmp, "/var/www/html/" + name)
        ''',
        "shutil.copyfile into webroot with user name.",
    )

    # --- File upload safe (10) ---
    add(
        cases,
        "file_upload",
        "u4_upload_s_token_hex_data_dir",
        False,
        '''
        def store_vault_blob():
            data = request.files["file"].read()
            name = secrets.token_hex(16) + ".bin"
            Path("/data/vault").joinpath(name).write_bytes(data)
        ''',
        "secrets.token_hex destination stored off webroot.",
    )
    add(
        cases,
        "file_upload",
        "u4_upload_s_uuid_payload_offweb",
        False,
        '''
        def uuid_payload_store():
            data = request.files["blob"].read()
            sub = str(uuid.uuid4())
            Path("/data/blobs/" + sub + "/payload.bin").write_bytes(data)
        ''',
        "UUID subdir with fixed payload name off webroot.",
    )
    add(
        cases,
        "file_upload",
        "u4_upload_s_reject_exec_random",
        False,
        '''
        def reject_executables():
            fn = request.files["f"].filename
            if fn.endswith(".py") or fn.endswith(".sh") or fn.endswith(".exe"):
                raise ValueError("blocked")
            request.files["f"].save("/data/inbox/" + secrets.token_hex(12) + ".bin")
        ''',
        "Reject executables then save random name under /data.",
    )
    add(
        cases,
        "file_upload",
        "u4_upload_s_hash_only_digest",
        False,
        '''
        def digest_upload():
            content = request.files["f"].read()
            return hashlib.sha256(content).hexdigest()
        ''',
        "Hash only; no file persist.",
    )
    add(
        cases,
        "file_upload",
        "u4_upload_s_fixed_logo_basename",
        False,
        '''
        def fixed_logo_write():
            data = request.files["logo"].read()
            open("/data/branding/logo.png", "wb").write(data)
        ''',
        "Fixed basename destination, not user-controlled.",
    )
    add(
        cases,
        "file_upload",
        "u4_upload_s_image_whitelist_random",
        False,
        '''
        def whitelist_images():
            fn = request.files["img"].filename
            ext = os.path.splitext(fn)[1].lower()
            if ext not in {".png", ".jpg", ".webp"}:
                raise ValueError("type")
            request.files["img"].save("/data/images/" + secrets.token_hex(8) + ext)
        ''',
        "Image whitelist plus random name off webroot.",
    )
    add(
        cases,
        "file_upload",
        "u4_upload_s_content_type_pdf_rand",
        False,
        '''
        def pdf_content_gate():
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
        "u4_upload_s_private_token_hex_save",
        False,
        '''
        def private_token_store():
            f = request.files["file"]
            f.save("/var/app/private/" + secrets.token_hex(16) + ".bin")
        ''',
        "Save off webroot with token_hex name.",
    )
    add(
        cases,
        "file_upload",
        "u4_upload_s_fixed_archive_name",
        False,
        '''
        def archive_fixed_dest():
            data = request.files["doc"].read()
            open("/data/store/current.archive", "wb").write(data)
        ''',
        "Outside webroot with fixed destination name.",
    )
    add(
        cases,
        "file_upload",
        "u4_upload_s_path_token_write",
        False,
        '''
        def path_token_blob():
            data = request.files["f"].read()
            Path("/data/objects/" + secrets.token_hex(16)).write_bytes(data)
        ''',
        "Path write with token_hex name off webroot.",
    )

    # --- IDOR vulnerable (10) ---
    add(
        cases,
        "idor",
        "u4_idor_v_objects_get_order_id",
        True,
        '''
        class Purchase:
            objects = None

        def open_purchase():
            token = request.args.get("purchase")
            selected = token
            return Purchase.objects.get(pk=selected)
        ''',
        "ORM get via pk from query param without ownership check.",
    )
    add(
        cases,
        "idor",
        "u4_idor_v_filter_user_id_param",
        True,
        '''
        def posts_by_user():
            uid = request.args.get("user_id")
            return Post.objects.filter(user_id=uid)
        ''',
        "filter(user_id=) from query param.",
    )
    add(
        cases,
        "idor",
        "u4_idor_v_filter_username_lookup",
        True,
        '''
        def member_by_name():
            name = request.args.get("username")
            return Member.objects.filter(username=name).first()
        ''',
        "filter(username=) without session bind.",
    )
    add(
        cases,
        "idor",
        "u4_idor_v_filter_email_lookup",
        True,
        '''
        def customer_by_email():
            email = request.args.get("email")
            return Customer.objects.filter(email=email).first()
        ''',
        "filter(email=) fetches arbitrary customer.",
    )
    add(
        cases,
        "idor",
        "u4_idor_v_db_query_item_key",
        True,
        '''
        def load_item_key():
            key = request.args.get("key")
            return db.query("SELECT * FROM items WHERE key = ?", key)
        ''',
        "db.query keyed by user-supplied key.",
    )
    add(
        cases,
        "idor",
        "u4_idor_v_json_document_id",
        True,
        '''
        class Dossier:
            objects = None

        def dossier_payload():
            payload = request.get_json()
            dossier_uuid = payload.get("dossier_uuid")
            return Dossier.objects.filter(uuid=dossier_uuid).first()
        ''',
        "JSON dossier_uuid selects resource without authz.",
    )
    add(
        cases,
        "idor",
        "u4_idor_v_nested_json_owner",
        True,
        '''
        def nested_owner_load():
            owner = request.json.get("meta", {}).get("owner_id")
            return Workspace.objects.get(id=owner)
        ''',
        "Nested json meta.owner_id used as identity.",
    )
    add(
        cases,
        "idor",
        "u4_idor_v_form_invoice_delete",
        True,
        '''
        class BillingNote:
            objects = None

        def remove_billing_note():
            note = request.form.get("note_id")
            BillingNote.objects.filter(pk=note).delete()
        ''',
        "Form note_id delete without owner verification.",
    )
    add(
        cases,
        "idor",
        "u4_idor_v_multihop_objects_get",
        True,
        '''
        def hop_report_get():
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
        "u4_idor_v_ticket_key_filter",
        True,
        '''
        def open_ticket():
            ticket_key = request.args.get("ticket_key")
            return Ticket.objects.filter(key=ticket_key).first()
        ''',
        "ticket_key from args drives filter without ownership.",
    )

    # --- IDOR safe (10) ---
    add(
        cases,
        "idor",
        "u4_idor_s_session_owner_filter",
        False,
        '''
        class Workspace:
            objects = None

        def list_my_workspaces():
            actor = session.get("uid")
            return Workspace.objects.filter(owner_id=actor).order_by("-created_at")
        ''',
        "Session-scoped owner filter; no client identity key.",
    )
    add(
        cases,
        "idor",
        "u4_idor_s_ownership_raise_guard",
        False,
        '''
        class CaseFile:
            objects = None

        def open_casefile():
            cid = request.args.get("cid")
            item = CaseFile.objects.get(pk=cid)
            if item.user_id != g.user.id:
                raise PermissionError("not owner")
            return item
        ''',
        "Load by id then enforce user_id == g.user.id.",
    )
    add(
        cases,
        "idor",
        "u4_idor_s_g_user_compare",
        False,
        '''
        def g_user_owned():
            rid = request.args.get("rid")
            row = Note.objects.get(id=rid)
            if row.owner_id != g.user.id:
                abort(403)
            return row
        ''',
        "g.user ownership compare before return.",
    )
    add(
        cases,
        "idor",
        "u4_idor_s_admin_is_admin_gate",
        False,
        '''
        def admin_list_all():
            if not session.get("is_admin"):
                abort(403)
            return Account.objects.all()
        ''',
        "Admin is_admin gate before broad listing.",
    )
    add(
        cases,
        "idor",
        "u4_idor_s_current_user_profile",
        False,
        '''
        class Settings:
            objects = None

        def edit_settings():
            me = current_user.id
            return Settings.objects.filter(account_id=me).first()
        ''',
        "Settings scoped to current_user.id only.",
    )
    add(
        cases,
        "idor",
        "u4_idor_s_static_slug_terms",
        False,
        '''
        def terms_page():
            return Page.objects.get(slug="terms-of-service")
        ''',
        "Static slug identity; not user-controlled.",
    )
    add(
        cases,
        "idor",
        "u4_idor_s_public_filter_flag",
        False,
        '''
        def public_posts():
            return Post.objects.filter(is_public=True).order_by("-id")
        ''',
        "Public filter only; no user identity key.",
    )
    add(
        cases,
        "idor",
        "u4_idor_s_aggregate_count",
        False,
        '''
        def post_count():
            return Post.objects.count()
        ''',
        "Aggregate count; no per-object identity access.",
    )
    add(
        cases,
        "idor",
        "u4_idor_s_log_only_access",
        False,
        '''
        def audit_view_attempt():
            target = request.args.get("target_id")
            logging.info("view_attempt target=%s actor=%s", target, session.get("uid"))
            return {"ok": True}
        ''',
        "Log-only of target id; no object fetch.",
    )
    add(
        cases,
        "idor",
        "u4_idor_s_get_then_owner_check",
        False,
        '''
        def get_then_check():
            mid = request.args.get("message_id")
            msg = Message.objects.get(id=mid)
            if msg.owner_id != session["user_id"]:
                raise PermissionError("not owner")
            return msg
        ''',
        "Get then owner check before return.",
    )
