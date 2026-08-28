from django.utils.safestring import mark_safe
from flask import request

def banner():
    text = request.args.get("text")
    safe_html = mark_safe(text)
    return safe_html
