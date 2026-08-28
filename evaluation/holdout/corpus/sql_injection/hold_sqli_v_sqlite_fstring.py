import sqlite3
from flask import request

def lookup(conn):
    email = request.form.get("email")
    conn.execute(f"SELECT id FROM accounts WHERE email = '{email}'")
