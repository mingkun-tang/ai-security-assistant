def patch_profile():
    pid = request.form.get("profile_id")
    bio = request.form.get("bio")
    Profile.objects.filter(id=pid).update(bio=bio)
