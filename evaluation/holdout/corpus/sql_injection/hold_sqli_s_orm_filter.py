from flask import request

class Product:
    objects = None

def find():
    sku = request.args.get("sku")
    return Product.objects.filter(sku=sku).first()
