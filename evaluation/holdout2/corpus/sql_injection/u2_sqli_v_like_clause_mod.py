def search(cur):
    term = request.args.get("term")
    cur.execute("SELECT * FROM docs WHERE body LIKE '%" + term + "%'")
