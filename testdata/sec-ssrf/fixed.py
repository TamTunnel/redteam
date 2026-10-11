# Fixed: fixed allowlisted endpoints only.
import requests


def fetch_profile():
    return requests.get("https://api.example.com/v1/profile", timeout=10).json()


def fetch_avatar():
    return requests.get("https://cdn.example.com/avatars/default.png", timeout=10)
