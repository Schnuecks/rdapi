"""Passkeys und Sicherheitsschlüssel (WebAuthn/FIDO2) für die Weboberfläche.

Ablauf in beide Richtungen: Der Server erzeugt eine Herausforderung (Optionen als JSON),
der Browser lässt sie vom Passkey unterschreiben, der Server prüft die Antwort. Die
eigentliche Prüfung übernimmt die Bibliothek webauthn.
"""

from __future__ import annotations

import json
import secrets
import sqlite3
from typing import Any
from urllib.parse import urlsplit

from webauthn import (
    base64url_to_bytes,
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import bytes_to_base64url
from webauthn.helpers.exceptions import InvalidAuthenticationResponse, InvalidRegistrationResponse
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from .db import now
from .security import token_hash

RP_NAME = "RDAPI"
CHALLENGE_SECONDS = 300
MAX_PER_USER = 20


class PasskeyError(Exception):
    """Fehler, die angezeigt werden (englischer Text = Übersetzungsschlüssel)."""


FAILED = "The passkey could not be verified. Please try again."
UNKNOWN = "This passkey is not known here."
EXPIRED = "The request has expired. Please try again."
TOO_MANY = "You already have the maximum number of passkeys."
MESSAGES = (FAILED, UNKNOWN, EXPIRED, TOO_MANY)


def relying_party(public_url: str, base_url: str) -> tuple[str, str]:
    """(RP-ID, Origin): Passkeys gelten für genau diese Adresse."""
    parts = urlsplit(public_url or base_url)
    origin = f"{parts.scheme}://{parts.netloc}"
    return parts.hostname or "", origin


def count(conn: sqlite3.Connection, user_id: int) -> int:
    return conn.execute("SELECT COUNT(*) FROM passkeys WHERE user_id = ?", (user_id,)).fetchone()[0]


def any_registered(conn: sqlite3.Connection) -> bool:
    return conn.execute("SELECT 1 FROM passkeys LIMIT 1").fetchone() is not None


def for_user(conn: sqlite3.Connection, user_id: int) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT * FROM passkeys WHERE user_id = ? ORDER BY created_at", (user_id,)
    ).fetchall()


def _descriptors(conn: sqlite3.Connection, user_id: int) -> list[PublicKeyCredentialDescriptor]:
    return [
        PublicKeyCredentialDescriptor(id=base64url_to_bytes(r["credential_id"]))
        for r in for_user(conn, user_id)
    ]


def _store_challenge(
    conn: sqlite3.Connection, challenge: bytes, purpose: str, user_id: int | None
) -> str:
    token = secrets.token_urlsafe(24)
    conn.execute(
        "INSERT INTO webauthn_challenges (token_hash, challenge, purpose, user_id, expires_at)"
        " VALUES (?, ?, ?, ?, ?)",
        (token_hash(token), challenge, purpose, user_id, now() + CHALLENGE_SECONDS),
    )
    return token


def _take_challenge(conn: sqlite3.Connection, token: str, purpose: str) -> sqlite3.Row:
    """Holt die Herausforderung und löscht sie; jede gilt genau einmal."""
    row = conn.execute(
        "SELECT * FROM webauthn_challenges WHERE token_hash = ? AND purpose = ?",
        (token_hash(token), purpose),
    ).fetchone()
    if row is None:
        raise PasskeyError(EXPIRED)
    conn.execute("DELETE FROM webauthn_challenges WHERE id = ?", (row["id"],))
    if row["expires_at"] < now():
        raise PasskeyError(EXPIRED)
    return row


def registration_options(conn: sqlite3.Connection, user: sqlite3.Row, rp_id: str) -> dict[str, Any]:
    if count(conn, user["id"]) >= MAX_PER_USER:
        raise PasskeyError(TOO_MANY)
    options = generate_registration_options(
        rp_id=rp_id,
        rp_name=RP_NAME,
        user_name=user["username"],
        user_id=f"rdapi-user-{user['id']}".encode(),
        user_display_name=user["display_name"] or user["username"],
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.PREFERRED,
        ),
        exclude_credentials=_descriptors(conn, user["id"]),
    )
    token = _store_challenge(conn, options.challenge, "register", user["id"])
    return {"token": token, "options": json.loads(options_to_json(options))}


def register(
    conn: sqlite3.Connection,
    user: sqlite3.Row,
    token: str,
    credential: dict[str, Any],
    name: str,
    rp_id: str,
    origin: str,
) -> None:
    row = _take_challenge(conn, token, "register")
    if row["user_id"] != user["id"]:
        raise PasskeyError(EXPIRED)
    try:
        verified = verify_registration_response(
            credential=credential,
            expected_challenge=row["challenge"],
            expected_rp_id=rp_id,
            expected_origin=origin,
        )
    except (InvalidRegistrationResponse, ValueError, KeyError, TypeError) as exc:
        raise PasskeyError(FAILED) from exc
    try:
        conn.execute(
            "INSERT INTO passkeys (user_id, credential_id, public_key, sign_count, name,"
            " created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (
                user["id"],
                bytes_to_base64url(verified.credential_id),
                verified.credential_public_key,
                verified.sign_count,
                name.strip()[:60] or "Passkey",
                now(),
            ),
        )
    except sqlite3.IntegrityError as exc:
        raise PasskeyError(FAILED) from exc


def authentication_options(
    conn: sqlite3.Connection, rp_id: str, user_id: int | None = None
) -> dict[str, Any]:
    """Ohne user_id: Anmeldung ohne Passwort (der Browser bietet die Passkeys für diese
    Adresse an). Mit user_id: zweiter Faktor, nur die Passkeys dieses Benutzers."""
    options = generate_authentication_options(
        rp_id=rp_id,
        allow_credentials=_descriptors(conn, user_id) if user_id else None,
        user_verification=UserVerificationRequirement.REQUIRED
        if user_id is None
        else UserVerificationRequirement.PREFERRED,
    )
    purpose = "login" if user_id is None else "second"
    token = _store_challenge(conn, options.challenge, purpose, user_id)
    return {"token": token, "options": json.loads(options_to_json(options))}


def authenticate(
    conn: sqlite3.Connection,
    token: str,
    credential: dict[str, Any],
    rp_id: str,
    origin: str,
    user_id: int | None = None,
) -> int:
    """Prüft die Antwort und liefert die Benutzer-ID des Passkeys."""
    row = _take_challenge(conn, token, "login" if user_id is None else "second")
    if row["user_id"] != user_id:
        raise PasskeyError(EXPIRED)
    key = conn.execute(
        "SELECT * FROM passkeys WHERE credential_id = ?", (str(credential.get("id", "")),)
    ).fetchone()
    if key is None or (user_id is not None and key["user_id"] != user_id):
        raise PasskeyError(UNKNOWN)
    try:
        verified = verify_authentication_response(
            credential=credential,
            expected_challenge=row["challenge"],
            expected_rp_id=rp_id,
            expected_origin=origin,
            credential_public_key=key["public_key"],
            credential_current_sign_count=key["sign_count"],
            # Ohne Passwort muss der Passkey die Person selbst prüfen (PIN, Fingerabdruck).
            require_user_verification=user_id is None,
        )
    except (InvalidAuthenticationResponse, ValueError, KeyError, TypeError) as exc:
        raise PasskeyError(FAILED) from exc
    conn.execute(
        "UPDATE passkeys SET sign_count = ?, last_used_at = ? WHERE id = ?",
        (verified.new_sign_count, now(), key["id"]),
    )
    return key["user_id"]
