# Fixed: no shell — argv list passed directly, shell defaults to False.
import subprocess


def list_dir(d):
    return subprocess.run(["ls", d], capture_output=True)


def disk_usage(target):
    return subprocess.run(["du", "-sh", target], capture_output=True)
