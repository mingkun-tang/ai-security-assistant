def fetch_record():
    rid = request.args.get("record_id")
    return db.query("SELECT * FROM records WHERE id = ?", rid)
