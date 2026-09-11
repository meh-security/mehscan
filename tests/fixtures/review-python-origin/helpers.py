import os


def read_local(filename):
    root = os.path.dirname(__file__)
    path = os.path.join(root, filename)
    return open(path, "r").read()


def write_source(content):
    root = os.path.dirname(__file__)
    path = os.path.join(root, "generated.py")
    handle = open(path, "w")
    handle.write(content)
    handle.close()
