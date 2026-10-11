# Vulnerable: predictable PRNG used for a reset token.
import random


def new_reset_token():
    token = str(random.randint(100000, 999999))
    return token
