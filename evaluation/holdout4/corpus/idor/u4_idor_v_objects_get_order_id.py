class Purchase:
    objects = None

def open_purchase():
    token = request.args.get("purchase")
    selected = token
    return Purchase.objects.get(pk=selected)
