"""Hand-written vulnerable fixture (weak hash). Never executed."""

import hashlib


def digest(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()
