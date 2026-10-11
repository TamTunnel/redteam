# Vulnerable: server fetches a caller-supplied URL.
import urllib.request

import requests


def fetch_profile(user_url):
    return requests.get(user_url).json()


def fetch_avatar(user_id):
    return requests.get("https://cdn.example.com/avatars/" + user_id)


def fetch_legacy(target):
    return urllib.request.urlopen(target).read()
