import subprocess
import yaml


def separated_process(request):
    host = request.POST.get("host")
    return subprocess.run(["dig", host], shell=False)


def safe_yaml(request):
    uploaded = request.FILES["document"]
    return yaml.safe_load(uploaded)
