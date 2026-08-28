def my_orders():
    uid = session["user_id"]
    return Order.objects.filter(user_id=uid)
