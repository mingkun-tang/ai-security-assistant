from flask import request

def filter_users(cursor):
    status = request.form.get("status")
    cursor.execute("UPDATE users SET active=1 WHERE status = '" + status + "'")
