def get_then_check():
    mid = request.args.get("message_id")
    msg = Message.objects.get(id=mid)
    if msg.owner_id != session["user_id"]:
        raise PermissionError("not owner")
    return msg
