def my_profile():
    return Profile.objects.get(user_id=current_user.id)
