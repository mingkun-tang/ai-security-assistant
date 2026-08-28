def subscriber_lookup(cursor):
    email = request.form.get("email")
    cursor.execute("SELECT * FROM newsletter WHERE email = '" + email + "'")
    return cursor.fetchall()
