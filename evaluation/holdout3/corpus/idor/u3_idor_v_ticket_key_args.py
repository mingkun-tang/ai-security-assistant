def open_ticket():
    ticket_key = request.args.get("ticket_key")
    return Ticket.objects.get(key=ticket_key)
