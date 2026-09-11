from . import generated
from .helpers import read_local, write_source


def normalize(value):
    return value.strip()


def read_route(request):
    filename = normalize(request.GET.get("filename"))
    return read_local(filename)


def write_route(request):
    source = request.POST.get("source")
    write_source(source)
    return generated.run()
