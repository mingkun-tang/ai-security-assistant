class Task:
    objects = None

def pending():
    return Task.objects.exclude(status="done")
