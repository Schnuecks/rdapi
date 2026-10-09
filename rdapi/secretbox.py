"""Verschlüsselung kleiner Geheimnisse in der Datenbank (TOTP-Schlüssel).

Mit RDAPI_SECRET_KEY werden die Geheimnisse mit AES-256-GCM verschlüsselt gespeichert;
der Schlüssel steht nur in der Konfiguration, nie in der Datenbank. Eine gestohlene
Sicherung enthält dann nichts, womit sich Codes erzeugen lassen. Ohne Schlüssel bleibt es
beim Klartext wie bisher.
"""

from __future__ import annotations

import base64
import logging
import os
import sqlite3

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

log = logging.getLogger("rdapi")

PREFIX = "enc:v1:"


def _aead(secret_key: str) -> AESGCM:
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"rdapi totp").derive(
        secret_key.encode()
    )
    return AESGCM(key)


def seal(secret_key: str, value: str) -> str:
    if not secret_key or not value:
        return value
    nonce = os.urandom(12)
    data = nonce + _aead(secret_key).encrypt(nonce, value.encode(), None)
    return PREFIX + base64.urlsafe_b64encode(data).decode()


def open_(secret_key: str, value: str) -> str:
    """Klartext zum gespeicherten Wert; leer, wenn er sich nicht entschlüsseln lässt."""
    if not value.startswith(PREFIX):
        return value
    if not secret_key:
        return ""
    try:
        data = base64.urlsafe_b64decode(value[len(PREFIX) :])
        return _aead(secret_key).decrypt(data[:12], data[12:], None).decode()
    except (ValueError, InvalidTag):
        return ""


def migrate(conn: sqlite3.Connection, secret_key: str) -> None:
    """Beim Start: vorhandene Klartext-Geheimnisse verschlüsseln, bzw. warnen, wenn
    verschlüsselte da sind, aber der Schlüssel fehlt oder nicht passt."""
    rows = conn.execute("SELECT id, totp_secret FROM users WHERE totp_secret != ''").fetchall()
    for row in rows:
        value = row["totp_secret"]
        if value.startswith(PREFIX):
            if not open_(secret_key, value):
                log.error(
                    "Cannot decrypt the two-factor key of user %s: RDAPI_SECRET_KEY is missing"
                    " or wrong. Two-factor codes of this user fail until the key is set again.",
                    row["id"],
                )
        elif secret_key:
            conn.execute(
                "UPDATE users SET totp_secret = ? WHERE id = ?",
                (seal(secret_key, value), row["id"]),
            )
