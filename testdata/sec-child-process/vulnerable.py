# Vulnerable: shell interpretation of (potentially) interpolated commands.
import os
import subprocess


def list_dir(d):
    return os.system("ls " + d)


def disk_usage(target):
    return subprocess.run("du -sh " + target, shell=True, capture_output=True)
