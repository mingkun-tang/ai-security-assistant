def totals():
    return Metric.objects.aggregate(total=Sum("value"))
