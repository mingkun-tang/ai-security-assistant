"""Generate Unseen Holdout #2 corpus (locked before first evaluation)."""

from __future__ import annotations

import json
import sys
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = Path(__file__).resolve().parent

if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from build_corpus_cases_rest import register_rest

CASES: list[dict] = []


def add(cat: str, id: str, vuln: bool, src: str, exp: str) -> None:
    CASES.append(
        {
            "id": id,
            "path": f"corpus/{cat}/{id}.py",
            "category": cat,
            "expected_vulnerable": vuln,
            "expected_issue_type": cat if vuln else None,
            "explanation": exp,
            "source": textwrap.dedent(src).strip() + "\n",
        }
    )


# SQL injection (20)
add(
    "sql_injection",
    "u2_sqli_v_insert_values_concat",
    True,
    'def register(cursor):\n    pin = request.form.get("pin")\n    cursor.execute("INSERT INTO pins VALUES (" + pin + ")")',
    "User value concatenated into INSERT statement.",
)
add(
    "sql_injection",
    "u2_sqli_v_like_clause_mod",
    True,
    'def search(cur):\n    term = request.args.get("term")\n    cur.execute("SELECT * FROM docs WHERE body LIKE \'%" + term + "%\'")',
    "LIKE clause built via string concatenation.",
)
add(
    "sql_injection",
    "u2_sqli_v_extra_where_list",
    True,
    'class Note:\n    objects = None\n\ndef list_notes(q):\n    clause = request.args.get("clause")\n    return Note.objects.extra(where=[clause])',
    "Django extra(where=[user]) injects into SQL.",
)
add(
    "sql_injection",
    "u2_sqli_v_four_hop_query",
    True,
    'def q(cur):\n    a = request.args.get("a")\n    b = a\n    c = b\n    d = c\n    cur.execute("DELETE FROM sessions WHERE token = \'" + d + "\'")',
    "Four-hop assignment chain into SQL text.",
)
add(
    "sql_injection",
    "u2_sqli_v_pipe_join_execute",
    True,
    'def run(cur):\n    col = request.form.get("col")\n    pieces = ["SELECT * FROM ledger ORDER BY ", col]\n    cur.execute("|".join(pieces))',
    "Pipe-joined fragments include user sort column.",
)
add(
    "sql_injection",
    "u2_sqli_v_percent_two_fields",
    True,
    'def lookup(cur):\n    a = request.args.get("a")\n    b = request.args.get("b")\n    cur.execute("SELECT * FROM pairs WHERE x=%s AND y=%s" % (a, b))',
    "Legacy percent formatting embeds user values in SQL.",
)
add(
    "sql_injection",
    "u2_sqli_v_orm_raw_fstring",
    True,
    'class Widget:\n    objects = None\n\ndef widgets(name):\n    n = request.args.get("name")\n    return Widget.objects.raw(f"SELECT id FROM widgets WHERE label = \'{n}\'")',
    "ORM raw() with f-string SQL.",
)
add(
    "sql_injection",
    "u2_sqli_v_update_concat",
    True,
    'def patch(cur):\n    val = request.form.get("val")\n    cur.execute("UPDATE settings SET value = \'" + val + "\' WHERE id = 1")',
    "UPDATE SET clause uses concatenated user text.",
)
add(
    "sql_injection",
    "u2_sqli_v_loop_join_fragments",
    True,
    'def dynamic(cur):\n    parts = ["SELECT * FROM events WHERE "]\n    filt = request.args.get("f")\n    parts.append(filt)\n    cur.execute("".join(parts))',
    "List accumulator builds dynamic WHERE from user filter.",
)
add(
    "sql_injection",
    "u2_sqli_v_union_concat",
    True,
    'def union(cur):\n    tbl = request.args.get("tbl")\n    cur.execute("SELECT id FROM users UNION SELECT id FROM " + tbl)',
    "UNION branch table name from user input.",
)

add(
    "sql_injection",
    "u2_sqli_s_text_named_bind",
    False,
    'def safe(cur):\n    email = request.form.get("email")\n    cur.execute("SELECT id FROM users WHERE email = :email", {"email": email})',
    "Named bind parameters isolate user email.",
)
add(
    "sql_injection",
    "u2_sqli_s_executemany_tuple",
    False,
    'def bulk(cur):\n    rows = request.json.get("rows")\n    cur.executemany("INSERT INTO batch(data) VALUES (%s)", rows)',
    "executemany uses parameter tuples, not SQL concatenation.",
)
add(
    "sql_injection",
    "u2_sqli_s_orm_exclude_static",
    False,
    'class Task:\n    objects = None\n\ndef pending():\n    return Task.objects.exclude(status="done")',
    "ORM exclude with static filter only.",
)
add(
    "sql_injection",
    "u2_sqli_s_static_select",
    False,
    'def count(cur):\n    cur.execute("SELECT COUNT(*) FROM metrics")',
    "No user input in SQL.",
)
add(
    "sql_injection",
    "u2_sqli_s_whitelist_column_map",
    False,
    'def sort_products(cur):\n    key = request.args.get("key")\n    allowed = {"name": "name", "price": "price"}\n    column = allowed.get(key, "name")\n    cur.execute("SELECT * FROM products ORDER BY " + column)',
    "User key selects among static allowlisted column names only.",
)
add(
    "sql_injection",
    "u2_sqli_s_parameterized_limit",
    False,
    'def page(cur):\n    n = request.args.get("n")\n    cur.execute("SELECT * FROM items LIMIT %s", (n,))',
    "LIMIT uses bound parameter.",
)
add(
    "sql_injection",
    "u2_sqli_s_user_logged_not_queried",
    False,
    'import logging\n\ndef audit(cur):\n    who = request.args.get("who")\n    logging.warning("audit by %s", who)\n    cur.execute("SELECT 1")',
    "User input logged but query is static.",
)
add(
    "sql_injection",
    "u2_sqli_s_in_static_ids",
    False,
    'def active(cur):\n    cur.execute("SELECT id FROM users WHERE id IN (10, 11, 12)")',
    "IN list is compile-time literals.",
)
add(
    "sql_injection",
    "u2_sqli_s_django_filter_static",
    False,
    'class Article:\n    objects = None\n\ndef published():\n    return Article.objects.filter(status="published")',
    "ORM filter on static status.",
)
add(
    "sql_injection",
    "u2_sqli_s_raw_with_params",
    False,
    'class Stat:\n    objects = None\n\ndef stats(day):\n    return Stat.objects.raw("SELECT * FROM stats WHERE day = %s", [day])',
    "raw() with parameter list.",
)

register_rest(add)


def main() -> None:
    if len(CASES) != 100:
        raise SystemExit(f"Expected 100 cases, got {len(CASES)}")
    categories = {}
    for c in CASES:
        categories.setdefault(c["category"], {"v": 0, "s": 0})
        if c["expected_vulnerable"]:
            categories[c["category"]]["v"] += 1
        else:
            categories[c["category"]]["s"] += 1
    for cat, counts in sorted(categories.items()):
        if counts["v"] != 10 or counts["s"] != 10:
            raise SystemExit(f"Category {cat} has {counts['v']} vuln / {counts['s']} safe (expected 10/10)")

    for case in CASES:
        dest = ROOT / case["path"]
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(case["source"], encoding="utf-8")

    manifest = {
        "version": "1.0",
        "description": "Unseen Holdout #2 — locked before first scanner evaluation",
        "scanner": "analyze_source",
        "checkpoint": "fff7b3b",
        "cases": [
            {
                "id": c["id"],
                "path": c["path"],
                "language": "python",
                "category": c["category"],
                "expected_vulnerable": c["expected_vulnerable"],
                "expected_issue_type": c["expected_issue_type"],
                "explanation": c["explanation"],
            }
            for c in CASES
        ],
    }
    (ROOT / "ground_truth.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )
    print(f"Generated {len(CASES)} cases under {ROOT}")


if __name__ == "__main__":
    main()
