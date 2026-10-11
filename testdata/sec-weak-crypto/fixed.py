# Fixed: SHA-256 for integrity; AES-GCM for encryption.
import hashlib

from Crypto.Cipher import AES


def hash_password(pw):
    return hashlib.sha256(pw.encode()).hexdigest()


def encrypt(data, key, nonce):
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.encrypt(data)
