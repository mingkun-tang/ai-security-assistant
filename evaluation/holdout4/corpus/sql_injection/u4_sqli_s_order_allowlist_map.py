def sorted_items(cursor):
    key = request.args.get("sort", "name")
    cols = {"name": "name", "price": "price", "created": "created_at"}
    col = cols.get(key, "name")
    cursor.execute(f"SELECT * FROM items ORDER BY {col}")
    return cursor.fetchall()
