def list_public():
    return Article.objects.filter(is_public=True)
