from flask import request

def lookup(cursor):
    email = request.form.get("email")
    cursor.execute(
        "SELECT id FROM accounts WHERE email = :email",
        {"email": email},
    )
