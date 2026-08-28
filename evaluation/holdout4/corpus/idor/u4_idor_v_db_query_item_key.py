def load_item_key():
    key = request.args.get("key")
    return db.query("SELECT * FROM items WHERE key = ?", key)
