def nested_owner_load():
    owner = request.json.get("meta", {}).get("owner_id")
    return Workspace.objects.get(id=owner)
