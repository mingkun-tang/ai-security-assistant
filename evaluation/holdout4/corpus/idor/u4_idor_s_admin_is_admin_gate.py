def admin_list_all():
    if not session.get("is_admin"):
        abort(403)
    return Account.objects.all()
