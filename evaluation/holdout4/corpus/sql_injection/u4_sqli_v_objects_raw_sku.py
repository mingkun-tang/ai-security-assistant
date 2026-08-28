def product_by_sku(request):
    sku = request.GET.get("sku")
    return Product.objects.raw(f"SELECT * FROM catalog_product WHERE sku = '{sku}'")
