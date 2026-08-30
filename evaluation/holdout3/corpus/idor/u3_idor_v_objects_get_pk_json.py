def pk_from_json():
    pk = request.json.get("pk")
    return Widget.objects.get(pk=pk)
