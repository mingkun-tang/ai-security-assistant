from flask import request

def search(cursor):
    user_id = request.args.get("q")
    cursor.execute(f"SELECT * FROM users WHERE name = {user_id}")
