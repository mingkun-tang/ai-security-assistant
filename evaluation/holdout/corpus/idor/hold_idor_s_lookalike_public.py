class Product:
    objects = None

def catalog():
    return Product.objects.filter(is_public=True).all()
