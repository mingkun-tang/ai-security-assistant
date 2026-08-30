class Workspace:
    objects = None

def list_mine():
    actor = session.get("uid")
    return Workspace.objects.filter(owner_id=actor).order_by("-created_at")
