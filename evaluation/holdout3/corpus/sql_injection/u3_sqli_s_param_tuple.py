def fetch_user(cursor):
    uid = request.args.get("uid")
    cursor.execute("SELECT * FROM users WHERE id = %s", (uid,))
