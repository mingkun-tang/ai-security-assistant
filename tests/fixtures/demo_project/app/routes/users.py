from flask import request

def search():
    user_id = request.args.get("id")
    cursor.execute("SELECT * FROM users WHERE id = " + user_id)
