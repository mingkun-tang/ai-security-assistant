from flask_login import current_user

class Order:
    objects = None

def my_orders():
    return Order.objects.filter(user_id=current_user.id).all()
