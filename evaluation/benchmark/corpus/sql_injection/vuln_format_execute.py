from flask import request

def search(cursor):
    user_id = request.args.get("id")
    cursor.execute("SELECT * FROM users WHERE id = {}".format(user_id))
