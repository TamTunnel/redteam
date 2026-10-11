# Fixed: bound parameters via DB-API placeholders.
def find_user(cursor, name):
    cursor.execute("SELECT * FROM users WHERE name = %s", (name,))


def find_by_id(cursor, uid):
    cursor.execute("SELECT * FROM users WHERE id = %s", (uid,))
