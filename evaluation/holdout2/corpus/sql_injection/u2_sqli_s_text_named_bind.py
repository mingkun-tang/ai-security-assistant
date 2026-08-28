def safe(cur):
    email = request.form.get("email")
    cur.execute("SELECT id FROM users WHERE email = :email", {"email": email})
