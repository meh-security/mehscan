def run(command, arguments):
    return subprocess.run_safe([command, arguments], shell=False)
