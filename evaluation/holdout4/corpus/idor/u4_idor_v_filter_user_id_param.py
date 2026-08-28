def posts_by_user():
    uid = request.args.get("user_id")
    return Post.objects.filter(user_id=uid)
