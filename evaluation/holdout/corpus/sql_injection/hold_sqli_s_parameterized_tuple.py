from flask import request

def by_status(cursor):
    status = request.args.get("status")
    cursor.execute("SELECT id FROM orders WHERE status = %s", (status,))
