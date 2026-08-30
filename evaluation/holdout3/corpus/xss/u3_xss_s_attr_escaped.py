import html

def btn():
    tip = request.args.get("tip")
    safe = html.escape(tip, quote=True)
    return f'<button title="{safe}">?</button>'
