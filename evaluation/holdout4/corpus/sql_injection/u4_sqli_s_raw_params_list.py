def products_in_category(request):
    cat = request.GET.get("cat")
    return Product.objects.raw(
        "SELECT * FROM catalog_product WHERE category_id = %s",
        [cat],
    )
