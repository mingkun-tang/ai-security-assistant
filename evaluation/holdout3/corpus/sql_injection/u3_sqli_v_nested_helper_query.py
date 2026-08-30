def lookup_user(cursor):
    def build(uid):
        q = "SELECT * FROM accounts WHERE id = '" + uid + "'"
        return q
    user_id = request.args.get("uid")
    cursor.execute(build(user_id))
