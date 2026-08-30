def find_by_email():
    email = request.args.get("email")
    return Customer.objects.filter(email=email).first()
