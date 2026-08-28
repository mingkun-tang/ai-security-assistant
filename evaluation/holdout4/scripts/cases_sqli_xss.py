"""Holdout #4 SQL injection and XSS case definitions."""

from __future__ import annotations

from case_helpers import add


def register(cases: list) -> None:
    # --- SQL injection: vulnerable (10) ---
    add(
        cases,
        "sql_injection",
        "u4_sqli_v_percent_execute_name",
        True,
        '''
        def find_member(cursor):
            name = request.args.get("name")
            q = "SELECT id, email FROM members WHERE name = '%s'" % name
            cursor.execute(q)
            return cursor.fetchone()
        ''',
        "Percent-formatting embeds request name into SQL before execute.",
    )
    add(
        cases,
        "sql_injection",
        "u4_sqli_v_fstring_delete_ticket",
        True,
        '''
        def purge_ticket(cursor):
            tid = request.form["ticket_id"]
            cursor.execute(f"DELETE FROM support_tickets WHERE id = {tid}")
        ''',
        "f-string DELETE interpolates user ticket id into SQL.",
    )
    add(
        cases,
        "sql_injection",
        "u4_sqli_v_order_concat_col",
        True,
        '''
        def list_events(cursor):
            sort_col = request.args.get("sort", "starts_at")
            sql = "SELECT * FROM events ORDER BY " + sort_col
            cursor.execute(sql)
            return cursor.fetchall()
        ''',
        "ORDER BY column name concatenated from query string.",
    )
    add(
        cases,
        "sql_injection",
        "u4_sqli_v_where_list_join",
        True,
        '''
        def audit_rows(cursor):
            status = request.args.get("status")
            parts = [
                "SELECT * FROM audit_log WHERE 1=1",
                "AND status = '" + status + "'",
                "ORDER BY created_at DESC",
            ]
            cursor.execute(" ".join(parts))
        ''',
        "Literal list of WHERE pieces joined; user status spliced into SQL.",
    )
    add(
        cases,
        "sql_injection",
        "u4_sqli_v_objects_raw_sku",
        True,
        '''
        def product_by_sku(request):
            sku = request.GET.get("sku")
            return Product.objects.raw(f"SELECT * FROM catalog_product WHERE sku = '{sku}'")
        ''',
        "Django objects.raw with f-string containing user SKU.",
    )
    add(
        cases,
        "sql_injection",
        "u4_sqli_v_session_concat_ref",
        True,
        '''
        def load_invoice(db_session):
            ref = request.args.get("ref")
            sql = "SELECT * FROM invoices WHERE reference = '" + ref + "'"
            return db_session.execute(sql)
        ''',
        "SQLAlchemy session.execute runs concatenated SQL with user ref.",
    )
    add(
        cases,
        "sql_injection",
        "u4_sqli_v_cursor_plus_email",
        True,
        '''
        def subscriber_lookup(cursor):
            email = request.form.get("email")
            cursor.execute("SELECT * FROM newsletter WHERE email = '" + email + "'")
            return cursor.fetchall()
        ''',
        "cursor.execute builds SELECT with + concatenation of form email.",
    )
    add(
        cases,
        "sql_injection",
        "u4_sqli_v_conditional_fragment",
        True,
        '''
        def search_orders(cursor):
            base = "SELECT * FROM orders WHERE customer_id = ?"
            params = [g.user.id]
            clause = request.args.get("clause")
            if clause:
                base = base + " AND " + clause
            cursor.execute(base, params)
        ''',
        "Optional user-supplied SQL fragment appended after a parameterized base.",
    )
    add(
        cases,
        "sql_injection",
        "u4_sqli_v_alias_like_chain",
        True,
        '''
        def fuzzy_title(db):
            import sqlalchemy as sa
            run = db.execute
            q = request.args.get("q")
            needle = q
            pattern = "%" + needle + "%"
            run("SELECT title FROM articles WHERE title LIKE '" + pattern + "'")
        ''',
        "Alias chain and multi-hop vars feed user term into LIKE concatenation.",
    )
    add(
        cases,
        "sql_injection",
        "u4_sqli_v_format_select_uid",
        True,
        '''
        def account_row(cursor):
            uid = request.args.get("uid")
            sql = "SELECT * FROM accounts WHERE user_id = '{}'".format(uid)
            cursor.execute(sql)
            return cursor.fetchone()
        ''',
        "str.format embeds user uid into SELECT before execute.",
    )

    # --- SQL injection: safe (10) ---
    add(
        cases,
        "sql_injection",
        "u4_sqli_s_param_tuple_email",
        False,
        '''
        def find_by_email(cursor):
            email = request.form.get("email")
            cursor.execute(
                "SELECT id FROM users WHERE email = ?",
                (email,),
            )
            return cursor.fetchone()
        ''',
        "Parameterized tuple keeps user email out of SQL text.",
    )
    add(
        cases,
        "sql_injection",
        "u4_sqli_s_named_bind_order",
        False,
        '''
        def order_detail(session):
            oid = request.args.get("oid")
            return session.execute(
                text("SELECT * FROM orders WHERE id = :oid"),
                {"oid": oid},
            )
        ''',
        "Named bind parameter for order id; SQL string is static.",
    )
    add(
        cases,
        "sql_injection",
        "u4_sqli_s_order_allowlist_map",
        False,
        '''
        def sorted_items(cursor):
            key = request.args.get("sort", "name")
            cols = {"name": "name", "price": "price", "created": "created_at"}
            col = cols.get(key, "name")
            cursor.execute(f"SELECT * FROM items ORDER BY {col}")
            return cursor.fetchall()
        ''',
        "ORDER BY taken only from allowlist map, not raw request value.",
    )
    add(
        cases,
        "sql_injection",
        "u4_sqli_s_static_select_active",
        False,
        '''
        def active_campaigns(cursor):
            _ = request.args.get("hint")
            cursor.execute("SELECT id, title FROM campaigns WHERE active = 1")
            return cursor.fetchall()
        ''',
        "Static SQL only; request hint is unused in the query.",
    )
    add(
        cases,
        "sql_injection",
        "u4_sqli_s_orm_filter_owner",
        False,
        '''
        def my_notes(request):
            return Note.objects.filter(owner_id=request.user.id, archived=False)
        ''',
        "ORM filter with static field names and session user id.",
    )
    add(
        cases,
        "sql_injection",
        "u4_sqli_s_raw_params_list",
        False,
        '''
        def products_in_category(request):
            cat = request.GET.get("cat")
            return Product.objects.raw(
                "SELECT * FROM catalog_product WHERE category_id = %s",
                [cat],
            )
        ''',
        "objects.raw with placeholder and params list.",
    )
    add(
        cases,
        "sql_injection",
        "u4_sqli_s_logged_input_static",
        False,
        '''
        def health_probe(cursor):
            probe = request.args.get("probe")
            app.logger.info("probe=%s", probe)
            cursor.execute("SELECT 1 AS ok")
            return cursor.fetchone()
        ''',
        "User input only logged; executed SQL is fully static.",
    )
    add(
        cases,
        "sql_injection",
        "u4_sqli_s_executemany_static",
        False,
        '''
        def bulk_flags(cursor):
            flags = request.json.get("flags", [])
            rows = [(f,) for f in flags]
            cursor.executemany(
                "INSERT INTO feature_flags(name) VALUES (?)",
                rows,
            )
        ''',
        "executemany with static INSERT and bound row params.",
    )
    add(
        cases,
        "sql_injection",
        "u4_sqli_s_whitelist_table_map",
        False,
        '''
        def export_table(cursor):
            name = request.args.get("table")
            allowed = {"users": "users", "orders": "orders", "items": "items"}
            table = allowed[name]
            cursor.execute("SELECT * FROM " + table + " LIMIT 100")
        ''',
        "Table name resolved via whitelist map before concatenation.",
    )
    add(
        cases,
        "sql_injection",
        "u4_sqli_s_bindparams_style",
        False,
        '''
        def invoice_by_ref(session):
            ref = request.args.get("ref")
            stmt = text("SELECT * FROM invoices WHERE reference = :ref").bindparams(ref=ref)
            return session.execute(stmt)
        ''',
        "SQLAlchemy text().bindparams binds user ref safely.",
    )

    # --- XSS: vulnerable (10) ---
    add(
        cases,
        "xss",
        "u4_xss_v_fstring_banner_html",
        True,
        '''
        def welcome_banner():
            who = request.args.get("who", "guest")
            return f"<div class='banner'>Hello {who}</div>"
        ''',
        "f-string HTML reflects query who without escaping.",
    )
    add(
        cases,
        "xss",
        "u4_xss_v_concat_div_msg",
        True,
        '''
        def flash_box():
            msg = request.args.get("msg")
            return "<div class='flash'>" + msg + "</div>"
        ''',
        "User message concatenated into HTML div.",
    )
    add(
        cases,
        "xss",
        "u4_xss_v_render_template_string",
        True,
        '''
        def preview_snippet():
            body = request.form.get("body")
            return render_template_string("<section>{{ body|safe }}</section>", body=body)
        ''',
        "render_template_string marks user body as safe HTML.",
    )
    add(
        cases,
        "xss",
        "u4_xss_v_markup_percent_title",
        True,
        '''
        def titled_panel():
            title = request.args.get("title")
            return Markup("<h2>%s</h2>") % title
        ''',
        "Markup percent-formats user title into HTML.",
    )
    add(
        cases,
        "xss",
        "u4_xss_v_httpresponse_concat",
        True,
        '''
        def django_notice(request):
            note = request.GET.get("note")
            return HttpResponse("<p class='notice'>" + note + "</p>")
        ''',
        "Django HttpResponse concatenates user note into HTML.",
    )
    add(
        cases,
        "xss",
        "u4_xss_v_href_attr_concat",
        True,
        '''
        def next_link():
            dest = request.args.get("next")
            return '<a href="' + dest + '">Continue</a>'
        ''',
        "href attribute built by concatenating user next URL.",
    )
    add(
        cases,
        "xss",
        "u4_xss_v_multihop_return_html",
        True,
        '''
        def profile_label():
            raw = request.args.get("label")
            mid = raw
            label = mid.strip()
            html = "<span class='label'>" + label + "</span>"
            return html
        ''',
        "Multi-hop assignment carries user label into returned HTML.",
    )
    add(
        cases,
        "xss",
        "u4_xss_v_join_middle_user",
        True,
        '''
        def card_line():
            name = request.args.get("name")
            parts = ["<li>", "User: ", name, "</li>"]
            return "".join(parts)
        ''',
        "User name placed in middle of HTML list then joined.",
    )
    add(
        cases,
        "xss",
        "u4_xss_v_make_response_html",
        True,
        '''
        def status_panel():
            status = request.args.get("status")
            body = "<div id='status'>" + status + "</div>"
            return make_response(body)
        ''',
        "make_response returns HTML with reflected status.",
    )
    add(
        cases,
        "xss",
        "u4_xss_v_error_page_reflect",
        True,
        '''
        def fail_page():
            detail = request.args.get("err")
            return (
                "<html><body><h1>Error</h1><pre>"
                + detail
                + "</pre></body></html>"
            ), 400
        ''',
        "Error page reflects user err detail in HTML pre block.",
    )

    # --- XSS: safe (10) ---
    add(
        cases,
        "xss",
        "u4_xss_s_jsonify_profile",
        False,
        '''
        def api_profile():
            name = request.args.get("name")
            return jsonify({"name": name, "ok": True})
        ''',
        "jsonify returns JSON, not HTML reflection.",
    )
    add(
        cases,
        "xss",
        "u4_xss_s_escape_then_concat",
        False,
        '''
        def safe_flash():
            msg = request.args.get("msg", "")
            safe = escape(msg)
            return "<div class='flash'>" + safe + "</div>"
        ''',
        "escape applied before concatenating into HTML.",
    )
    add(
        cases,
        "xss",
        "u4_xss_s_bleach_clean_bio",
        False,
        '''
        def user_bio():
            bio = request.form.get("bio", "")
            cleaned = bleach.clean(bio, tags=["b", "i"], strip=True)
            return "<div class='bio'>" + cleaned + "</div>"
        ''',
        "bleach.clean sanitizes bio before HTML wrap.",
    )
    add(
        cases,
        "xss",
        "u4_xss_s_static_markup_banner",
        False,
        '''
        def site_banner():
            _ = request.args.get("campaign")
            return Markup("<div class='banner'>Welcome back</div>")
        ''',
        "Static Markup string; campaign query unused in output.",
    )
    add(
        cases,
        "xss",
        "u4_xss_s_render_template_file",
        False,
        '''
        def show_dashboard():
            title = request.args.get("title", "Home")
            return render_template("dashboard.html", title=title)
        ''',
        "File-based render_template; autoescape handles title.",
    )
    add(
        cases,
        "xss",
        "u4_xss_s_redirect_only",
        False,
        '''
        def go_home():
            nxt = request.args.get("next", "/")
            if not nxt.startswith("/"):
                nxt = "/"
            return redirect(nxt)
        ''',
        "Redirect response only; no HTML body with user data.",
    )
    add(
        cases,
        "xss",
        "u4_xss_s_log_static_html",
        False,
        '''
        def maintenance_page():
            note = request.args.get("note")
            app.logger.info("maintenance note=%s", note)
            return "<html><body><p>Down for maintenance</p></body></html>"
        ''',
        "User note logged only; returned HTML is static.",
    )
    add(
        cases,
        "xss",
        "u4_xss_s_escape_fstring",
        False,
        '''
        def greet_user():
            who = request.args.get("who", "guest")
            return f"<p>Hello {escape(who)}</p>"
        ''',
        "f-string HTML uses escape around user who.",
    )
    add(
        cases,
        "xss",
        "u4_xss_s_no_html_output",
        False,
        '''
        def record_click():
            target = request.args.get("target")
            metrics.incr("click", tags={"target": target})
            return ("", 204)
        ''',
        "No HTML response body; input used only for metrics.",
    )
    add(
        cases,
        "xss",
        "u4_xss_s_template_static_ctx",
        False,
        '''
        def about_page():
            _ = request.args.get("ref")
            return render_template("about.html", year=2026, product="Acme")
        ''',
        "Template rendered with static context only.",
    )
