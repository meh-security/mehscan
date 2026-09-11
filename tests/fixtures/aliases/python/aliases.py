import subprocess as sp
from subprocess import Popen as launch


def review(command):
    sp.Popen(command)
    launch(command)


def shadowed(sp, command):
    sp.Popen(command)
