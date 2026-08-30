def identity_by_username():
    handle = request.args.get("handle")
    return User.objects.filter(username=handle).first()
