# Fixed: argv lists, no shell — nothing is assembled into a command string.
import subprocess


def show_log(branch):
    subprocess.run(["git", "log", "--oneline", branch])


def list_dir(d):
    subprocess.run(["ls", "-la", d])
