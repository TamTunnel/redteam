# Vulnerable: SQL built by concatenation / f-string interpolation.
def find_user(cursor, name):
    cursor.execute("SELECT * FROM users WHERE name = '" + name + "'")


def find_by_id(cursor, uid):
    cursor.execute(f"SELECT * FROM users WHERE id = {uid}")
