def fixed_lookup(request):
    return Record.objects.filter(id=1).first()


def fixed_string_lookup(request):
    return Record.objects.filter(id="system").first()


def dynamic_lookup(request):
    return Record.objects.filter(id=request.POST.get("record_id")).first()
