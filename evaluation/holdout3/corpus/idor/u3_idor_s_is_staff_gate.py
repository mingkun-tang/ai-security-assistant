def staff_user_view():
    uid = request.args.get("uid")
    if not g.user.is_staff:
        raise PermissionError()
    return User.objects.get(id=uid)
