def list_sorted(cursor):
    key = request.args.get("sort")
    cols = {"created": "created_at", "title": "title"}
    col = cols.get(key, "created_at")
    cursor.execute("SELECT * FROM articles ORDER BY " + col)
