# Vulnerable: redirect target built from request data.
from flask import redirect, request


def login():
    dest = request.args.get("next", "/")
    return redirect("/go/" + dest)


def welcome(username):
    return redirect(f"/welcome/{username}")
