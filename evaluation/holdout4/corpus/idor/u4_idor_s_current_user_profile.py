class Settings:
    objects = None

def edit_settings():
    me = current_user.id
    return Settings.objects.filter(account_id=me).first()
