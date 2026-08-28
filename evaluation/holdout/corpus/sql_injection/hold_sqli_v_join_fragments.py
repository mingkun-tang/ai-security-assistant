from flask import request

def search(cursor):
    column = request.args.get("sort")
    parts = ["SELECT name FROM products ORDER BY ", column]
    cursor.execute("".join(parts))
