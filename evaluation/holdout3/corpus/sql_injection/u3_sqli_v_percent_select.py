def by_email(cursor):
    email = request.form.get("email")
    cursor.execute("SELECT * FROM subscribers WHERE email = '%s'" % email)
