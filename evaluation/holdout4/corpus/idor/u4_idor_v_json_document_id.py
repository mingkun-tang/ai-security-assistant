class Dossier:
    objects = None

def dossier_payload():
    payload = request.get_json()
    dossier_uuid = payload.get("dossier_uuid")
    return Dossier.objects.filter(uuid=dossier_uuid).first()
