def featured(cursor):
    cursor.execute("SELECT * FROM products WHERE id IN (1, 2, 3)")
