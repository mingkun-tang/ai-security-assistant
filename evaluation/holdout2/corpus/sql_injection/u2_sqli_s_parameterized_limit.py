def page(cur):
    n = request.args.get("n")
    cur.execute("SELECT * FROM items LIMIT %s", (n,))
