class Coupon:
    objects = None

def coupons():
    code = request.args.get("code")
    return Coupon.objects.raw("SELECT * FROM coupons WHERE code = '{}'".format(code))
