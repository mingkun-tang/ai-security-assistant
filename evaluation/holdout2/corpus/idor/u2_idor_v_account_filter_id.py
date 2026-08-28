def account_view():
    acc = request.args.get("account")
    return Account.objects.filter(id=acc).first()
