def user_bio():
    bio = request.form.get("bio", "")
    cleaned = bleach.clean(bio, tags=["b", "i"], strip=True)
    return "<div class='bio'>" + cleaned + "</div>"
