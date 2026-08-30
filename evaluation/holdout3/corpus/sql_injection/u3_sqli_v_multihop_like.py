def fuzzy_find(cursor):
    raw = request.args.get("needle")
    alias = raw
    pattern = "%" + alias + "%"
    cursor.execute("SELECT * FROM notes WHERE body LIKE '" + pattern + "'")
