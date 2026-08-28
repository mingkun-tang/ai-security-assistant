def search_orders(cursor):
    base = "SELECT * FROM orders WHERE customer_id = ?"
    params = [g.user.id]
    clause = request.args.get("clause")
    if clause:
        base = base + " AND " + clause
    cursor.execute(base, params)
