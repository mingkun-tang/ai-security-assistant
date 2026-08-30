class Ticket:
    objects = None

def open_tickets():
    return Ticket.objects.filter(state="open")
