import subprocess


def execute(command):
    return subprocess.Popen(command, shell=True)


def handler(request):
    command = request.GET.get("command")
    return execute(command)
