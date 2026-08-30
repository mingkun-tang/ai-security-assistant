def from_body():
    payload = request.get_json()
    caption = payload.get("caption")
    return "<figure>" + caption + "</figure>"
