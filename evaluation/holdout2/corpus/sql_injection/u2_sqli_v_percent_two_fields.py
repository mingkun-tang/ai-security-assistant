def lookup(cur):
    a = request.args.get("a")
    b = request.args.get("b")
    cur.execute("SELECT * FROM pairs WHERE x=%s AND y=%s" % (a, b))
