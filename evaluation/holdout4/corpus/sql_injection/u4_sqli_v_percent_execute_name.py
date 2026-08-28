def find_member(cursor):
    name = request.args.get("name")
    q = "SELECT id, email FROM members WHERE name = '%s'" % name
    cursor.execute(q)
    return cursor.fetchone()
