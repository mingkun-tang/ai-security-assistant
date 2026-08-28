def account_row(cursor):
    uid = request.args.get("uid")
    sql = "SELECT * FROM accounts WHERE user_id = '{}'".format(uid)
    cursor.execute(sql)
    return cursor.fetchone()
