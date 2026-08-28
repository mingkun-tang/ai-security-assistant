def list_events(cursor):
    sort_col = request.args.get("sort", "starts_at")
    sql = "SELECT * FROM events ORDER BY " + sort_col
    cursor.execute(sql)
    return cursor.fetchall()
