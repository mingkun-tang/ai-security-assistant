def my_notes(request):
    return Note.objects.filter(owner_id=request.user.id, archived=False)
