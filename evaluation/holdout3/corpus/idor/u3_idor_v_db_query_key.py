def load_row():
    key = request.args.get("key")
    return db.query("SELECT * FROM items WHERE key = ?", key)
