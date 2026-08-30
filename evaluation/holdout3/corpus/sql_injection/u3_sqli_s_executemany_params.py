def import_rows(cursor):
    rows = request.json.get("rows")
    cursor.executemany("INSERT INTO imports(payload) VALUES (%s)", rows)
