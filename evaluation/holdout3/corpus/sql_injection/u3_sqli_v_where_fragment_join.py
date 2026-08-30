def filter_orders(cursor):
    fragments = ["SELECT * FROM orders WHERE 1=1"]
    if request.args.get("paid") == "1":
        fragments.append("AND paid = 1")
    extra = request.args.get("extra")
    if extra:
        fragments.append(extra)
    cursor.execute(" ".join(fragments))
