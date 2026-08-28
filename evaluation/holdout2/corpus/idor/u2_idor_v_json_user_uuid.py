def load_profile():
    uid = request.json.get("user_uuid")
    return User.objects.get(pk=uid)
