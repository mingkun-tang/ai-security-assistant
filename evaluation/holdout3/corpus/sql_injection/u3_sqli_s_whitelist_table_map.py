def dump_table(cursor):
    name = request.args.get("name")
    allowed = {"users": "users", "roles": "roles"}
    table = allowed.get(name, "users")
    cursor.execute("SELECT * FROM " + table)
