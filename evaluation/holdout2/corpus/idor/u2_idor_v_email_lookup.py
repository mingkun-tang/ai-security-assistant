def by_email():
    email = request.args.get("email")
    return Account.objects.filter(email=email).first()
