def active_users(cursor):
    cursor.execute("SELECT * FROM users WHERE active = 1")
