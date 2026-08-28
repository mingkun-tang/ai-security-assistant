def bulk_flags(cursor):
    flags = request.json.get("flags", [])
    rows = [(f,) for f in flags]
    cursor.executemany(
        "INSERT INTO feature_flags(name) VALUES (?)",
        rows,
    )
