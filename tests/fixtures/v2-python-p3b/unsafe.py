import base64
import pickle
import re
import subprocess
import yaml
from django.views.decorators.csrf import csrf_exempt
from xml.dom.pulldom import parseString
from xml.sax import make_parser
from xml.sax.handler import feature_external_ges


@csrf_exempt
def command(request):
    domain = request.POST.get("domain")
    domain = re.sub(r"^https?://", "", domain)
    if request.POST.get("tool") == "dig":
        program = "dig {}".format(domain)
    else:
        program = "nslookup {}".format(domain)
    return subprocess.Popen(program, shell=True)


def evaluate(request):
    expression = request.POST.get("expression")
    return eval(expression)


def restore(request):
    token = request.COOKIES.get("token")
    decoded = base64.b64decode(token)
    return pickle.loads(decoded)


def yaml_upload(request):
    uploaded = request.FILES["document"]
    return yaml.load(uploaded, yaml.Loader)


def xml_parse(request):
    parser = make_parser()
    parser.setFeature(feature_external_ges, True)
    return parseString(request.body.decode("utf-8"), parser=parser)
