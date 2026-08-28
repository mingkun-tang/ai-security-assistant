def purge_ticket(cursor):
    tid = request.form["ticket_id"]
    cursor.execute(f"DELETE FROM support_tickets WHERE id = {tid}")
