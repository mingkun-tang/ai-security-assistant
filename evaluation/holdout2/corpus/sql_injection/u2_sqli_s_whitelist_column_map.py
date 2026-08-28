def sort_products(cur):
    key = request.args.get("key")
    allowed = {"name": "name", "price": "price"}
    column = allowed.get(key, "name")
    cur.execute("SELECT * FROM products ORDER BY " + column)
