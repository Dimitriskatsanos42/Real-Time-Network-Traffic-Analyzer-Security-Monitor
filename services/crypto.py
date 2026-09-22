"""Encryption helpers for sensitive user-owned data."""

from cryptography.fernet import Fernet, InvalidToken
from flask import current_app


def _cipher():
    return Fernet(current_app.config["DATA_ENCRYPTION_KEY"])


def encrypt_value(value):
    if value is None or value == "":
        return None
    return _cipher().encrypt(value.encode("utf-8")).decode("ascii")


def decrypt_value(value):
    if not value:
        return None
    try:
        return _cipher().decrypt(value.encode("ascii")).decode("utf-8")
    except (InvalidToken, ValueError):
        return None