def safe_flash():
    msg = request.args.get("msg", "")
    safe = escape(msg)
    return "<div class='flash'>" + safe + "</div>"
