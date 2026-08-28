def public_posts():
    return Post.objects.filter(is_public=True).order_by("-id")
