import os
import subprocess


def run(command):
    os.system(command)
    subprocess.Popen(command)

