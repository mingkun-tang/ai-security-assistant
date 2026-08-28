def find_by_email(cursor):
    email = request.form.get("email")
    cursor.execute(
        "SELECT id FROM users WHERE email = ?",
        (email,),
    )
    return cursor.fetchone()
