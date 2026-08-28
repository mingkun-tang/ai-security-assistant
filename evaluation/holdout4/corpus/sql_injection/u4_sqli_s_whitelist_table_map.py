def export_table(cursor):
    name = request.args.get("table")
    allowed = {"users": "users", "orders": "orders", "items": "items"}
    table = allowed[name]
    cursor.execute("SELECT * FROM " + table + " LIMIT 100")
