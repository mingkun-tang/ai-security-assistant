def public_posts():
    return Article.objects.filter(is_public=True)
