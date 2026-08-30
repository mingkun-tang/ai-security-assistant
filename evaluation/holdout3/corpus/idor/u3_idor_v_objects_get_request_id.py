def show_order():
    oid = request.args.get("order_id")
    return Order.objects.get(id=oid)
