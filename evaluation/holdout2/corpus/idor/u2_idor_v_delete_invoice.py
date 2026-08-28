def delete_invoice():
    inv = request.form.get("invoice_id")
    Invoice.objects.filter(id=inv).delete()
