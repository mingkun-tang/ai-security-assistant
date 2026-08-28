def register(cursor):
    pin = request.form.get("pin")
    cursor.execute("INSERT INTO pins VALUES (" + pin + ")")
