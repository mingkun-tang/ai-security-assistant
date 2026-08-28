from flask import request

class Order:
    objects = None

def my_orders(current_user):
    return Order.objects.filter(user_id=current_user.id)
