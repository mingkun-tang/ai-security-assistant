def nested_owner():
    owner = request.json.get("meta", {}).get("owner_id")
    return Document.objects.get(id=owner)
