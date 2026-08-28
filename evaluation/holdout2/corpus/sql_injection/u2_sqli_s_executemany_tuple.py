def bulk(cur):
    rows = request.json.get("rows")
    cur.executemany("INSERT INTO batch(data) VALUES (%s)", rows)
