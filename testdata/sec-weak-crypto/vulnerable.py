# Vulnerable: broken hash and cipher.
import hashlib

import Crypto.Cipher.DES


def hash_password(pw):
    return hashlib.md5(pw.encode()).hexdigest()


def legacy_decrypt(data, key):
    cipher = Crypto.Cipher.DES.new(key)
    return cipher.decrypt(data)
