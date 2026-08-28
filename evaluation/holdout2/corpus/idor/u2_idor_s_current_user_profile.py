def edit_me():
    return Profile.objects.get(user_id=current_user.id)
