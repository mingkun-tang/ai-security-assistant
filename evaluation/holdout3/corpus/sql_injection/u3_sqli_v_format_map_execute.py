def load_row(cursor):
    rid = request.args.get("rid")
    sql = "SELECT * FROM rows WHERE id = '{rid}'".format_map({"rid": rid})
    cursor.execute(sql)
