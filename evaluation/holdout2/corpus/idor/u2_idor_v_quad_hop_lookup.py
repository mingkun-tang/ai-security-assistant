def quad_lookup():
    x = request.args.get("x")
    y = x
    z = y
    w = z
    return Order.objects.get(id=w)
