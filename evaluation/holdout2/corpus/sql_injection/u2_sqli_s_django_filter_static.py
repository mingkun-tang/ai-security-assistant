class Article:
    objects = None

def published():
    return Article.objects.filter(status="published")
