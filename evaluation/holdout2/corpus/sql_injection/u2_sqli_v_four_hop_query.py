def q(cur):
    a = request.args.get("a")
    b = a
    c = b
    d = c
    cur.execute("DELETE FROM sessions WHERE token = '" + d + "'")
