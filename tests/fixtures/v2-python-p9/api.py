import connexion
import requests
from jinja2 import Template as JinjaTemplate


def fetch_file(name):
    return open(name).read()


def fetch_url(endpoint):
    return requests.get(url=endpoint, timeout=2).text


def unsafe_file(payload):
    name = payload.get("filename")
    return fetch_file(name)


def safe_file():
    return fetch_file("safe.txt")


def unsafe_url(payload):
    endpoint = payload.get("url")
    return fetch_url(endpoint)


def safe_url():
    return fetch_url("https://example.test/image.png")


def unsafe_template(payload):
    expression = payload.get("expression")
    template = JinjaTemplate("result: " + expression)
    return {"result": template.render()}


def safe_template():
    template = JinjaTemplate("result: 49")
    return {"result": template.render()}
