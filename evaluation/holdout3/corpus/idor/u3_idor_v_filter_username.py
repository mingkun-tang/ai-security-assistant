def lookup_by_name():
    name = request.args.get("username")
    return Member.objects.filter(username=name).first()
