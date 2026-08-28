def django_notice(request):
    note = request.GET.get("note")
    return HttpResponse("<p class='notice'>" + note + "</p>")
