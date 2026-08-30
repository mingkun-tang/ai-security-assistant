def announce():
    body = request.POST.get("body")
    return mark_safe("<section>" + body + "</section>")
