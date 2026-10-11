# Vulnerable: command string assembled from parts, run through a shell.
import os
import subprocess


def show_log(branch):
    os.system("git log --oneline " + branch)


def list_dir(d):
    subprocess.run(f"ls -la {d}", shell=True)
