from flask import request

def title_block():
    title = request.args.get("title")
    return "<title>%s</title>" % title
