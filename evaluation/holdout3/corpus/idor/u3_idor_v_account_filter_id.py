def view_account():
    acc = request.args.get("account_id")
    return Account.objects.filter(id=acc).first()
