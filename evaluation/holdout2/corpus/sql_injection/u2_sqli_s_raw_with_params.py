class Stat:
    objects = None

def stats(day):
    return Stat.objects.raw("SELECT * FROM stats WHERE day = %s", [day])
