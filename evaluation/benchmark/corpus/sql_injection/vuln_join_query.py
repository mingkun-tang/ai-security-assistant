from flask import request

def search(cursor):
    table = request.args.get("table")
    cursor.execute("SELECT * FROM " + table)
