from flask import request

class Invoice:
    objects = None

def remove():
    invoice_id = request.args.get("invoice_id")
    Invoice.objects.filter(id=invoice_id).delete()
