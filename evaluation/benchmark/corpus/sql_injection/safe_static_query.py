def list_users(cursor):
    cursor.execute("SELECT id, email FROM users LIMIT 100")
