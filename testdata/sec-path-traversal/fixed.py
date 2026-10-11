# Fixed: serves one fixed file — user input never becomes a path.
def read_defaults():
    with open("/var/app/data/defaults.json") as f:
        return f.read()
