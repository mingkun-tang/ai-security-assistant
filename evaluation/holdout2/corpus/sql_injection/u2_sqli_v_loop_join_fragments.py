def dynamic(cur):
    parts = ["SELECT * FROM events WHERE "]
    filt = request.args.get("f")
    parts.append(filt)
    cur.execute("".join(parts))
