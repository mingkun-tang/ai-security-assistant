from django.utils.html import format_html
from flask import request

def link():
    url = request.args.get("url")
    return format_html("<a href='{}'>home</a>", url)
