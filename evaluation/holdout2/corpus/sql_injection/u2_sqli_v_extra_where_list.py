class Note:
    objects = None

def list_notes(q):
    clause = request.args.get("clause")
    return Note.objects.extra(where=[clause])
