def bulk_tag(cursor):
    tag = request.form.get("tag")
    sql = "INSERT INTO tags(name) VALUES ('" + tag + "')"
    rows = [(i,) for i in range(3)]
    cursor.executemany(sql, rows)
