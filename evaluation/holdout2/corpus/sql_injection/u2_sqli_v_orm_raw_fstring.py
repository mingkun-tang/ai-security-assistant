class Widget:
    objects = None

def widgets(name):
    n = request.args.get("name")
    return Widget.objects.raw(f"SELECT id FROM widgets WHERE label = '{n}'")
