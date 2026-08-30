def by_uuid():
    uid = request.args.get("uuid")
    return Resource.objects.get(uuid=uid)
