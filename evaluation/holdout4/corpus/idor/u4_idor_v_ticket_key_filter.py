def open_ticket():
    ticket_key = request.args.get("ticket_key")
    return Ticket.objects.filter(key=ticket_key).first()
