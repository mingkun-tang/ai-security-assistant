def flash_box():
    msg = request.args.get("msg")
    return "<div class='flash'>" + msg + "</div>"
