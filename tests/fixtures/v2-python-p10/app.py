import os


def direct_write(request):
    code = request.POST.get("code")
    target = os.path.join(os.path.dirname(__file__), "generated/worker.py")
    handle = open(target, "w")
    handle.write(code)


def keyword_mode(request):
    payload = request.POST.get("payload")
    stream = open("generated/task.py", mode="wb")
    stream.write(payload)


def ordinary_data_file(request):
    content = request.POST.get("content")
    handle = open("notes.txt", "w")
    handle.write(content)


def unrelated_writer(request, buffer):
    content = request.POST.get("content")
    buffer.write(content)


def rebound_handle(request):
    content = request.POST.get("content")
    handle = open("generated/first.py", "w")
    handle = get_writer()
    handle.write(content)


def fixed_content():
    handle = open("generated/static.py", "w")
    handle.write("print('fixed')")
