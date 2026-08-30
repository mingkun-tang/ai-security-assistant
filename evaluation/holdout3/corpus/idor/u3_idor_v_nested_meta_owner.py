def nested_meta_owner():
    owner = request.json.get("meta", {}).get("owner_id")
    return Workspace.objects.get(id=owner)
