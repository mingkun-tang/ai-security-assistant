def union(cur):
    tbl = request.args.get("tbl")
    cur.execute("SELECT id FROM users UNION SELECT id FROM " + tbl)
