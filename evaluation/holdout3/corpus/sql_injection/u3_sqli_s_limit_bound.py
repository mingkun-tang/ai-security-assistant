def page(cursor):
    n = request.args.get("n")
    cursor.execute("SELECT * FROM events LIMIT :n", {"n": n})
