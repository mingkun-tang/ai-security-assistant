from flask import request

def search(cursor):
    email = request.args.get("email")
    cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
