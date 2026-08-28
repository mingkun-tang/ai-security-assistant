from flask import request

class Order:
    objects = None

def order_detail():
    order_id = request.args.get("order_id")
    return Order.objects.get(id=order_id)
