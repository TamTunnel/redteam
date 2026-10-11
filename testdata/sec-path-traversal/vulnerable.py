# Vulnerable: user-controlled path reaches open().
def read_upload(name):
    return open("/var/app/data/" + name).read()


def read_config(user_path):
    with open(user_path) as f:
        return f.read()
