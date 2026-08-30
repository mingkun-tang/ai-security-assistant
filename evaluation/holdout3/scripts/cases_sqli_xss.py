"""Holdout #3 SQL injection and XSS case definitions."""

from __future__ import annotations

from case_helpers import add


def register(cases: list) -> None:
    # --- SQL injection: vulnerable (15) ---
    add(
        cases,
        "sql_injection",
        "u3_sqli_v_text_format",
        True,
        '''
        def fetch_invoice(session):
            inv = request.args.get("inv")
            stmt = text("SELECT * FROM invoices WHERE ref = '{}'".format(inv))
            return session.execute(stmt)
        ''',
        "SQLAlchemy text() SQL built with str.format of user input.",
    )
    add(
        cases,
        "sql_injection",
        "u3_sqli_v_text_fstring",
        True,
        '''
        def find_sku(session):
            sku = request.args.get("sku")
            return session.execute(text(f"SELECT id FROM catalog WHERE sku = '{sku}'"))
        ''',
        "SQLAlchemy text() wrapped around an f-string containing user input.",
    )
    add(
        cases,
        "sql_injection",
        "u3_sqli_v_executemany_built",
        True,
        '''
        def bulk_tag(cursor):
            tag = request.form.get("tag")
            sql = "INSERT INTO tags(name) VALUES ('" + tag + "')"
            rows = [(i,) for i in range(3)]
            cursor.executemany(sql, rows)
        ''',
        "executemany called with string-built SQL; params do not sanitize the query text.",
    )
    add(
        cases,
        "sql_injection",
        "u3_sqli_v_order_by_concat",
        True,
        '''
        def sorted_posts(cursor):
            direction = request.args.get("dir")
            cursor.execute("SELECT * FROM posts ORDER BY created_at " + direction)
        ''',
        "ORDER BY direction concatenated from request input.",
    )
    add(
        cases,
        "sql_injection",
        "u3_sqli_v_where_fragment_join",
        True,
        '''
        def filter_orders(cursor):
            fragments = ["SELECT * FROM orders WHERE 1=1"]
            if request.args.get("paid") == "1":
                fragments.append("AND paid = 1")
            extra = request.args.get("extra")
            if extra:
                fragments.append(extra)
            cursor.execute(" ".join(fragments))
        ''',
        "Conditional WHERE fragments appended then joined; user fragment reaches SQL.",
    )
    add(
        cases,
        "sql_injection",
        "u3_sqli_v_nested_helper_query",
        True,
        '''
        def lookup_user(cursor):
            def build(uid):
                q = "SELECT * FROM accounts WHERE id = '" + uid + "'"
                return q
            user_id = request.args.get("uid")
            cursor.execute(build(user_id))
        ''',
        "Nested helper builds SQL from local variable then outer execute runs it.",
    )
    add(
        cases,
        "sql_injection",
        "u3_sqli_v_percent_select",
        True,
        '''
        def by_email(cursor):
            email = request.form.get("email")
            cursor.execute("SELECT * FROM subscribers WHERE email = '%s'" % email)
        ''',
        "Percent-format embeds user email into SELECT.",
    )
    add(
        cases,
        "sql_injection",
        "u3_sqli_v_format_map_execute",
        True,
        '''
        def load_row(cursor):
            rid = request.args.get("rid")
            sql = "SELECT * FROM rows WHERE id = '{rid}'".format_map({"rid": rid})
            cursor.execute(sql)
        ''',
        "format_map substitutes user id into SQL before execute.",
    )
    add(
        cases,
        "sql_injection",
        "u3_sqli_v_builder_extend_join",
        True,
        '''
        def search_docs(cursor):
            builder = ["SELECT title FROM docs"]
            term = request.args.get("q")
            builder.extend(["WHERE body LIKE '%", term, "%'"])
            cursor.execute("".join(builder))
        ''',
        "Query builder list extended with user term then joined into SQL.",
    )
    add(
        cases,
        "sql_injection",
        "u3_sqli_v_delete_concat_id",
        True,
        '''
        def remove_session(cursor):
            sid = request.form.get("sid")
            cursor.execute("DELETE FROM sessions WHERE id = " + sid)
        ''',
        "DELETE statement concatenates user id into SQL.",
    )
    add(
        cases,
        "sql_injection",
        "u3_sqli_v_update_fstring_set",
        True,
        '''
        def rename_label(cursor):
            label = request.form.get("label")
            cursor.execute(f"UPDATE folders SET name = '{label}' WHERE id = 1")
        ''',
        "UPDATE SET clause built via f-string with user label.",
    )
    add(
        cases,
        "sql_injection",
        "u3_sqli_v_union_table_input",
        True,
        '''
        def export_ids(cursor):
            table = request.args.get("table")
            cursor.execute(f"SELECT id FROM primary_keys UNION ALL SELECT id FROM {table}")
        ''',
        "UNION ALL second table name taken from user input.",
    )
    add(
        cases,
        "sql_injection",
        "u3_sqli_v_objects_raw_format",
        True,
        '''
        class Coupon:
            objects = None

        def coupons():
            code = request.args.get("code")
            return Coupon.objects.raw("SELECT * FROM coupons WHERE code = '{}'".format(code))
        ''',
        "Django objects.raw with str.format of user code.",
    )
    add(
        cases,
        "sql_injection",
        "u3_sqli_v_session_execute_concat",
        True,
        '''
        def audit_trail(session):
            actor = request.args.get("actor")
            session.execute("SELECT * FROM audit WHERE actor = '" + actor + "'")
        ''',
        "session.execute with concatenated actor string.",
    )
    add(
        cases,
        "sql_injection",
        "u3_sqli_v_multihop_like",
        True,
        '''
        def fuzzy_find(cursor):
            raw = request.args.get("needle")
            alias = raw
            pattern = "%" + alias + "%"
            cursor.execute("SELECT * FROM notes WHERE body LIKE '" + pattern + "'")
        ''',
        "Multi-hop alias of user input into LIKE clause via concatenation.",
    )

    # --- SQL injection: safe (15) ---
    add(
        cases,
        "sql_injection",
        "u3_sqli_s_param_tuple",
        False,
        '''
        def fetch_user(cursor):
            uid = request.args.get("uid")
            cursor.execute("SELECT * FROM users WHERE id = %s", (uid,))
        ''',
        "Parameterized execute with tuple binding.",
    )
    add(
        cases,
        "sql_injection",
        "u3_sqli_s_named_bind",
        False,
        '''
        def by_slug(cursor):
            slug = request.args.get("slug")
            cursor.execute("SELECT * FROM pages WHERE slug = :slug", {"slug": slug})
        ''',
        "Named bind :slug keeps user value out of SQL text.",
    )
    add(
        cases,
        "sql_injection",
        "u3_sqli_s_executemany_params",
        False,
        '''
        def import_rows(cursor):
            rows = request.json.get("rows")
            cursor.executemany("INSERT INTO imports(payload) VALUES (%s)", rows)
        ''',
        "executemany with static SQL and parameter rows.",
    )
    add(
        cases,
        "sql_injection",
        "u3_sqli_s_order_allowlist",
        False,
        '''
        def list_sorted(cursor):
            key = request.args.get("sort")
            cols = {"created": "created_at", "title": "title"}
            col = cols.get(key, "created_at")
            cursor.execute("SELECT * FROM articles ORDER BY " + col)
        ''',
        "ORDER BY column chosen from static allowlist map.",
    )
    add(
        cases,
        "sql_injection",
        "u3_sqli_s_static_select",
        False,
        '''
        def health(cursor):
            cursor.execute("SELECT 1 FROM dual")
        ''',
        "Static SELECT with no user input.",
    )
    add(
        cases,
        "sql_injection",
        "u3_sqli_s_orm_filter_static",
        False,
        '''
        class Ticket:
            objects = None

        def open_tickets():
            return Ticket.objects.filter(state="open")
        ''',
        "ORM filter uses only a static literal.",
    )
    add(
        cases,
        "sql_injection",
        "u3_sqli_s_raw_params_list",
        False,
        '''
        class Score:
            objects = None

        def scores(day):
            return Score.objects.raw("SELECT * FROM scores WHERE day = %s", [day])
        ''',
        "raw() with params list isolates the day value.",
    )
    add(
        cases,
        "sql_injection",
        "u3_sqli_s_input_logged_only",
        False,
        '''
        import logging

        def ping(cursor):
            who = request.args.get("who")
            logging.info("ping from %s", who)
            cursor.execute("SELECT version()")
        ''',
        "User input only logged; SQL is static.",
    )
    add(
        cases,
        "sql_injection",
        "u3_sqli_s_text_bindparams",
        False,
        '''
        def load_item(session):
            item_id = request.args.get("id")
            stmt = text("SELECT * FROM items WHERE id = :id").bindparams(id=item_id)
            return session.execute(stmt)
        ''',
        "text() with bindparams for user id.",
    )
    add(
        cases,
        "sql_injection",
        "u3_sqli_s_whitelist_table_map",
        False,
        '''
        def dump_table(cursor):
            name = request.args.get("name")
            allowed = {"users": "users", "roles": "roles"}
            table = allowed.get(name, "users")
            cursor.execute("SELECT * FROM " + table)
        ''',
        "Table name selected from whitelist map only.",
    )
    add(
        cases,
        "sql_injection",
        "u3_sqli_s_limit_bound",
        False,
        '''
        def page(cursor):
            n = request.args.get("n")
            cursor.execute("SELECT * FROM events LIMIT :n", {"n": n})
        ''',
        "LIMIT uses a bound parameter.",
    )
    add(
        cases,
        "sql_injection",
        "u3_sqli_s_orm_exclude_static",
        False,
        '''
        class Job:
            objects = None

        def active_jobs():
            return Job.objects.exclude(status="archived")
        ''',
        "ORM exclude with static status only.",
    )
    add(
        cases,
        "sql_injection",
        "u3_sqli_s_in_literal_ids",
        False,
        '''
        def featured(cursor):
            cursor.execute("SELECT * FROM products WHERE id IN (1, 2, 3)")
        ''',
        "IN clause uses compile-time literal ids.",
    )
    add(
        cases,
        "sql_injection",
        "u3_sqli_s_user_in_comment_log",
        False,
        '''
        import logging

        def report(cursor):
            note = request.args.get("note")
            logging.debug("operator note: %s", note)
            # note is for operators only
            cursor.execute("SELECT COUNT(*) FROM reports")
        ''',
        "User value appears in log/comment only; query is static.",
    )
    add(
        cases,
        "sql_injection",
        "u3_sqli_s_format_then_param",
        False,
        '''
        import logging

        def greet_then_query(cursor):
            name = request.args.get("name")
            msg = "hello {}".format(name)
            logging.info(msg)
            cursor.execute("SELECT * FROM profiles WHERE active = %s", (True,))
        ''',
        "Safe format of non-SQL string then separate parameterized query.",
    )

    # --- XSS: vulnerable (15) ---
    add(
        cases,
        "xss",
        "u3_xss_v_format_map_html",
        True,
        '''
        def greet():
            name = request.args.get("name")
            return "<h1>Hi {name}</h1>".format_map({"name": name})
        ''',
        "format_map injects user name into HTML.",
    )
    add(
        cases,
        "xss",
        "u3_xss_v_nested_fstring_href",
        True,
        '''
        def link_out():
            target = request.args.get("url")
            inner = f'href="{target}"'
            return f"<a {inner}>go</a>"
        ''',
        "Nested f-string builds href attribute from user URL.",
    )
    add(
        cases,
        "xss",
        "u3_xss_v_render_template_string",
        True,
        '''
        def preview():
            title = request.args.get("title")
            return render_template_string("<h2>" + title + "</h2>")
        ''',
        "Jinja render_template_string builds template source from user title.",
    )
    add(
        cases,
        "xss",
        "u3_xss_v_markup_percent",
        True,
        '''
        def banner():
            msg = request.args.get("msg")
            return Markup("<div class='banner'>%s</div>" % msg)
        ''',
        "Markup with percent-formatting of user message.",
    )
    add(
        cases,
        "xss",
        "u3_xss_v_script_string_user",
        True,
        '''
        def bootstrap_js():
            token = request.args.get("token")
            return "<script>var t = '" + token + "';</script>"
        ''',
        "User token embedded in JS string inside a script tag.",
    )
    add(
        cases,
        "xss",
        "u3_xss_v_httpresponse_concat",
        True,
        '''
        def profile(HttpResponse):
            nick = request.GET.get("nick")
            return HttpResponse("<p>Welcome " + nick + "</p>")
        ''',
        "Django-style HttpResponse concatenates user nick into HTML.",
    )
    add(
        cases,
        "xss",
        "u3_xss_v_multihop_span",
        True,
        '''
        def label():
            raw = request.args.get("label")
            mid = raw
            final = mid
            return "<span>" + final + "</span>"
        ''',
        "Multi-hop assignment into span HTML sink.",
    )
    add(
        cases,
        "xss",
        "u3_xss_v_builder_list_join",
        True,
        '''
        def card():
            title = request.args.get("title")
            parts = ["<article><h3>", title, "</h3></article>"]
            return "".join(parts)
        ''',
        "Builder list joined with unsanitized user title.",
    )
    add(
        cases,
        "xss",
        "u3_xss_v_conditional_html_branch",
        True,
        '''
        def status():
            mode = request.args.get("mode")
            if mode == "ok":
                return "<p>ok</p>"
            detail = request.args.get("detail")
            return "<p>error: " + detail + "</p>"
        ''',
        "Conditional HTML branch embeds user detail when not ok.",
    )
    add(
        cases,
        "xss",
        "u3_xss_v_json_field_html",
        True,
        '''
        def from_body():
            payload = request.get_json()
            caption = payload.get("caption")
            return "<figure>" + caption + "</figure>"
        ''',
        "JSON body field written into HTML without escaping.",
    )
    add(
        cases,
        "xss",
        "u3_xss_v_title_attr_sink",
        True,
        '''
        def tip():
            tip = request.args.get("tip")
            return '<button title="' + tip + '">help</button>'
        ''',
        "User tip reflected into title attribute.",
    )
    add(
        cases,
        "xss",
        "u3_xss_v_make_response_html",
        True,
        '''
        def flash():
            note = request.args.get("note")
            return make_response("<div>" + note + "</div>")
        ''',
        "make_response with HTML concatenation of user note.",
    )
    add(
        cases,
        "xss",
        "u3_xss_v_mark_safe_user",
        True,
        '''
        def announce():
            body = request.POST.get("body")
            return mark_safe("<section>" + body + "</section>")
        ''',
        "mark_safe applied to HTML containing user body.",
    )
    add(
        cases,
        "xss",
        "u3_xss_v_format_into_render",
        True,
        '''
        def page():
            heading = request.args.get("h")
            tmpl = "<header>{}</header>".format(heading)
            return render_template_string(tmpl)
        ''',
        "User heading formatted into template string then rendered.",
    )
    add(
        cases,
        "xss",
        "u3_xss_v_error_page_plus",
        True,
        '''
        def fail():
            reason = request.args.get("reason")
            return "<h1>Error</h1><p>" + reason + "</p>"
        ''',
        "Error page reflects user reason via string +.",
    )

    # --- XSS: safe (15) ---
    add(
        cases,
        "xss",
        "u3_xss_s_jsonify",
        False,
        '''
        def api_msg():
            msg = request.args.get("msg")
            return jsonify({"message": msg})
        ''',
        "jsonify returns JSON, not HTML reflection.",
    )
    add(
        cases,
        "xss",
        "u3_xss_s_html_escape_concat",
        False,
        '''
        import html

        def safe_greet():
            name = request.args.get("name")
            return "<p>Hi " + html.escape(name) + "</p>"
        ''',
        "html.escape before concat into HTML.",
    )
    add(
        cases,
        "xss",
        "u3_xss_s_bleach_clean",
        False,
        '''
        def comment():
            text = request.form.get("text")
            cleaned = bleach.clean(text)
            return "<div>" + cleaned + "</div>"
        ''',
        "bleach.clean then HTML wrap.",
    )
    add(
        cases,
        "xss",
        "u3_xss_s_markup_static",
        False,
        '''
        def footer():
            return Markup("<footer>Acme Corp</footer>")
        ''',
        "Markup with static HTML only.",
    )
    add(
        cases,
        "xss",
        "u3_xss_s_render_template_file",
        False,
        '''
        def home():
            return render_template("home.html", year=2026)
        ''',
        "render_template file with static context.",
    )
    add(
        cases,
        "xss",
        "u3_xss_s_redirect_only",
        False,
        '''
        def go():
            return redirect("/dashboard")
        ''',
        "Redirect only; no HTML body with user data.",
    )
    add(
        cases,
        "xss",
        "u3_xss_s_escape_fstring",
        False,
        '''
        import html

        def hello():
            name = request.args.get("name")
            safe = html.escape(name)
            return f"<p>Hello {safe}</p>"
        ''',
        "escape then f-string into HTML.",
    )
    add(
        cases,
        "xss",
        "u3_xss_s_log_static_html",
        False,
        '''
        import logging

        def notify():
            who = request.args.get("who")
            logging.info("visitor %s", who)
            return "<p>ok</p>"
        ''',
        "User logged only; returned HTML is static.",
    )
    add(
        cases,
        "xss",
        "u3_xss_s_json_response_dict",
        False,
        '''
        def payload():
            q = request.args.get("q")
            return {"ok": True, "q": q}, 200, {"Content-Type": "application/json"}
        ''',
        "JSON response dict, not HTML sink.",
    )
    add(
        cases,
        "xss",
        "u3_xss_s_escape_api",
        False,
        '''
        def chip():
            label = request.args.get("label")
            return "<span>" + escape(label) + "</span>"
        ''',
        "format_html-style escape() before HTML wrap.",
    )
    add(
        cases,
        "xss",
        "u3_xss_s_no_html_output",
        False,
        '''
        def store():
            note = request.form.get("note")
            cache = {}
            cache["note"] = note
            return None
        ''',
        "No HTML output; value stored only.",
    )
    add(
        cases,
        "xss",
        "u3_xss_s_hardcoded_banner",
        False,
        '''
        def banner():
            unused = request.args.get("x")
            return "<div class='banner'>Maintenance window</div>"
        ''',
        "Hardcoded banner HTML; request unused in output.",
    )
    add(
        cases,
        "xss",
        "u3_xss_s_template_year_only",
        False,
        '''
        def release_notes():
            return render_template("changelog.html", build="1.0.0", channel="stable")
        ''',
        "Static template with compile-time context only.",
    )
    add(
        cases,
        "xss",
        "u3_xss_s_markup_escape_user",
        False,
        '''
        import html

        def box():
            user = request.args.get("user")
            return Markup(html.escape(user))
        ''',
        "Markup(escape(user)) marks escaped content only.",
    )
    add(
        cases,
        "xss",
        "u3_xss_s_attr_escaped",
        False,
        '''
        import html

        def btn():
            tip = request.args.get("tip")
            safe = html.escape(tip, quote=True)
            return f'<button title="{safe}">?</button>'
        ''',
        "Safe attribute with escaped value.",
    )
