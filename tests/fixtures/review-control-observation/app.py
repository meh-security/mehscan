import html
from django.http import HttpResponse


def conditional_output(value, encoded):
    output = html.escape(value) if encoded else value
    return HttpResponse(output)
