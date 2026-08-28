def find_user():
    name = request.args.get("username")
    return User.objects.filter(username=name).first()
