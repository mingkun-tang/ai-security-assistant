def admin_fetch_user():
    uid = request.args.get("uid")
    if not g.user.is_admin:
        raise PermissionError()
    return User.objects.get(id=uid)
