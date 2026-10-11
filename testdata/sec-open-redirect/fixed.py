# Fixed: framework URL builder — no user input in the target.
from flask import redirect, url_for


def login():
    return redirect(url_for("dashboard"))
