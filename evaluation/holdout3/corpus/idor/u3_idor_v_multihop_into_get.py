def hop_get():
    x = request.args.get("x")
    y = x
    z = y
    return Report.objects.get(id=z)
