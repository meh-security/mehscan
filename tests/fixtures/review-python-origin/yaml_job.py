import yaml


stream = open("/opt/application/trusted.yaml", "r")
settings = yaml.load(stream)
