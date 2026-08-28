def active(cur):
    cur.execute("SELECT id FROM users WHERE id IN (10, 11, 12)")
