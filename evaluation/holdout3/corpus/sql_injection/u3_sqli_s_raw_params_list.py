class Score:
    objects = None

def scores(day):
    return Score.objects.raw("SELECT * FROM scores WHERE day = %s", [day])
