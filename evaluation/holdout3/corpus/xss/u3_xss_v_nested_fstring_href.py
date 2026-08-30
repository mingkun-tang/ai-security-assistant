def link_out():
    target = request.args.get("url")
    inner = f'href="{target}"'
    return f"<a {inner}>go</a>"
