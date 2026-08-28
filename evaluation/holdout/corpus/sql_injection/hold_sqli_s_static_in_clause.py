def active(cursor):
    cursor.execute("SELECT id FROM users WHERE status IN (1, 2, 3)")
