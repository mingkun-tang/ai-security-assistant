class Config:
    objects = None

def site_config():
    return Config.objects.get(id=1)
