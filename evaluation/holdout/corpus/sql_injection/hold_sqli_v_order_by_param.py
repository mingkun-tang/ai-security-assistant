from flask import request

def list_items(cursor):
    order = request.args.get("order", "name")
    cursor.execute("SELECT id, name FROM items ORDER BY " + order)
