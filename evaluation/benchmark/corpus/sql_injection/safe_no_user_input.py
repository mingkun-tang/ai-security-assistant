def count_users(cursor):
    cursor.execute("SELECT COUNT(*) FROM users")
