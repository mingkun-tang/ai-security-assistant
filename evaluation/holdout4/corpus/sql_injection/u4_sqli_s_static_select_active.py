def active_campaigns(cursor):
    _ = request.args.get("hint")
    cursor.execute("SELECT id, title FROM campaigns WHERE active = 1")
    return cursor.fetchall()
