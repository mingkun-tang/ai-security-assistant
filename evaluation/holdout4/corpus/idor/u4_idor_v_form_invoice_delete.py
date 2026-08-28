class BillingNote:
    objects = None

def remove_billing_note():
    note = request.form.get("note_id")
    BillingNote.objects.filter(pk=note).delete()
