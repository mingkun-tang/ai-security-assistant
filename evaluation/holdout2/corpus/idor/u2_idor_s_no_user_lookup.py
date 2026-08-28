def stats():
    return Metric.objects.aggregate(total=Sum("value"))
