def profile(HttpResponse):
    nick = request.GET.get("nick")
    return HttpResponse("<p>Welcome " + nick + "</p>")
