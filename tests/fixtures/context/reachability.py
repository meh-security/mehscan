import os


def after_raise(command):
    raise RuntimeError("stop")
    os.system(command)
