"""Anmeldung über einen OpenID-Connect-Anbieter (Authorization Code mit PKCE).

Der Anbieter (z. B. Authelia) prüft Passwort und zweiten Faktor; RDAPI ordnet die
Person einem Konto zu. Der ID-Token kommt direkt und über TLS vom Token-Endpunkt; deshalb
genügt es nach OpenID Connect Core 3.1.3.7, Aussteller, Empfänger, Ablauf und Nonce zu
prüfen, ohne die Signatur selbst nachzurechnen.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import re
import secrets
import sqlite3
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any

from .config import Settings
from .db import now
from .security import create_user, log_activity, token_hash

log = logging.getLogger("rdapi.oidc")

FLOW_SECONDS = 300
DISCOVERY_SECONDS = 3600
HTTP_TIMEOUT = 10
SCOPES = "openid profile email groups"


class OidcError(Exception):
    """Fehler, die der Person angezeigt werden (englischer Text = Übersetzungsschlüssel)."""


# Texte, die die Weboberfläche anzeigt; für die Übersetzung gesammelt.
FAILED = "The sign-in with the provider failed. Please try again."
EXPIRED = "The sign-in has expired. Please sign in again."
NO_ACCOUNT = "There is no account for you yet. Please ask an admin to create one."
DISABLED = "Your account is disabled."
MESSAGES = (FAILED, EXPIRED, NO_ACCOUNT, DISABLED)


def _http_json(url: str, data: dict[str, str] | None = None, token: str = "") -> dict:
    """GET (ohne data) oder POST als Formular; Antwort als JSON. In Tests ersetzt."""
    body = urllib.parse.urlencode(data).encode() if data is not None else None
    req = urllib.request.Request(url, data=body, headers={"Accept": "application/json"})
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:  # noqa: S310
            return json.loads(resp.read().decode())
    except (urllib.error.URLError, ValueError, TimeoutError) as exc:
        log.warning("OIDC request to %s failed: %s", url, exc)
        raise OidcError(FAILED) from exc


_discovery: dict[str, tuple[float, dict]] = {}
_discovery_lock = threading.Lock()


def discovery(issuer: str) -> dict:
    with _discovery_lock:
        cached = _discovery.get(issuer)
        if cached and cached[0] > time.time():
            return cached[1]
    doc = _http_json(f"{issuer}/.well-known/openid-configuration")
    for key in ("issuer", "authorization_endpoint", "token_endpoint"):
        if not isinstance(doc.get(key), str):
            raise OidcError(FAILED)
    with _discovery_lock:
        _discovery[issuer] = (time.time() + DISCOVERY_SECONDS, doc)
    return doc


def redirect_uri(cfg: Settings, base_url: str) -> str:
    return (cfg.public_url or base_url.rstrip("/")) + "/oidc/callback"


def _pkce() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
    return verifier, challenge.decode().rstrip("=")


def start_flow(
    conn: sqlite3.Connection,
    cfg: Settings,
    base_url: str,
    kind: str,
    *,
    next_url: str = "/",
    device_id: str = "",
    device_uuid: str = "",
    client_info: str = "",
) -> tuple[str, str, str]:
    """Legt eine Anmeldung an. Liefert (Adresse beim Anbieter, state, App-Code)."""
    doc = discovery(cfg.oidc_issuer)
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(24)
    verifier, challenge = _pkce()
    app_code = secrets.token_urlsafe(24) if kind == "app" else ""
    conn.execute(
        "INSERT INTO oidc_flows (state_hash, kind, nonce, verifier, next, app_code_hash,"
        " device_id, device_uuid, client_info, expires_at)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            token_hash(state),
            kind,
            nonce,
            verifier,
            next_url,
            token_hash(app_code) if app_code else "",
            device_id,
            device_uuid,
            client_info,
            now() + FLOW_SECONDS,
        ),
    )
    params = {
        "response_type": "code",
        "client_id": cfg.oidc_client_id,
        "redirect_uri": redirect_uri(cfg, base_url),
        "scope": SCOPES,
        "state": state,
        "nonce": nonce,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    sep = "&" if "?" in doc["authorization_endpoint"] else "?"
    return doc["authorization_endpoint"] + sep + urllib.parse.urlencode(params), state, app_code


def load_flow(conn: sqlite3.Connection, state: str) -> sqlite3.Row | None:
    row = conn.execute(
        "SELECT * FROM oidc_flows WHERE state_hash = ?", (token_hash(state),)
    ).fetchone()
    if row is None or row["expires_at"] < now():
        return None
    return row


def _jwt_payload(token: str) -> dict:
    try:
        payload = token.split(".")[1]
        return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    except (IndexError, ValueError) as exc:
        raise OidcError(FAILED) from exc


def exchange(cfg: Settings, base_url: str, flow: sqlite3.Row, code: str) -> dict[str, Any]:
    """Tauscht den Code beim Anbieter ein und liefert die Angaben zur Person."""
    doc = discovery(cfg.oidc_issuer)
    tokens = _http_json(
        doc["token_endpoint"],
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri(cfg, base_url),
            "client_id": cfg.oidc_client_id,
            "client_secret": cfg.oidc_client_secret,
            "code_verifier": flow["verifier"],
        },
    )
    id_token = tokens.get("id_token")
    if not isinstance(id_token, str):
        raise OidcError(FAILED)
    claims = _jwt_payload(id_token)
    aud = claims.get("aud")
    audiences = aud if isinstance(aud, list) else [aud]
    if (
        claims.get("iss") != doc["issuer"]
        or cfg.oidc_client_id not in audiences
        or not isinstance(claims.get("exp"), int | float)
        or claims["exp"] < time.time()
        or not secrets.compare_digest(str(claims.get("nonce", "")), flow["nonce"])
        or not claims.get("sub")
    ):
        log.warning("OIDC id_token rejected (issuer, audience, expiry or nonce)")
        raise OidcError(FAILED)
    access = tokens.get("access_token")
    if doc.get("userinfo_endpoint") and isinstance(access, str):
        info = _http_json(doc["userinfo_endpoint"], token=access)
        if info.get("sub") == claims["sub"]:
            claims = {**claims, **info}
    return claims


@dataclass(frozen=True)
class Person:
    sub: str
    username: str
    email: str
    email_verified: bool
    name: str
    groups: tuple[str, ...]


def person(claims: dict[str, Any]) -> Person:
    groups = claims.get("groups")
    email = str(claims.get("email") or "")
    username = str(claims.get("preferred_username") or email.split("@")[0] or "")
    return Person(
        sub=str(claims["sub"]),
        username=re.sub(r"[^\w.@-]", "", username)[:64],
        email=email[:200],
        email_verified=claims.get("email_verified") is True,
        name=str(claims.get("name") or "")[:100],
        groups=tuple(str(g) for g in groups) if isinstance(groups, list) else (),
    )


def user_for(conn: sqlite3.Connection, cfg: Settings, who: Person) -> sqlite3.Row:
    """Konto zur Person: über die dauerhafte Verknüpfung, sonst über den Benutzernamen oder
    die bestätigte E-Mail-Adresse (und dann verknüpfen), sonst neu anlegen."""
    row = conn.execute("SELECT * FROM users WHERE oidc_sub = ?", (who.sub,)).fetchone()
    if row is None and who.username:
        row = conn.execute(
            "SELECT * FROM users WHERE username = ? AND oidc_sub = ''", (who.username,)
        ).fetchone()
    if row is None and who.email and who.email_verified:
        row = conn.execute(
            "SELECT * FROM users WHERE email = ? COLLATE NOCASE AND oidc_sub = ''", (who.email,)
        ).fetchone()
    if row is None:
        if not cfg.oidc_create_users or not who.username:
            raise OidcError(NO_ACCOUNT)
        # Zufälliges Passwort, das niemand kennt: Anmeldung nur über den Anbieter, bis ein
        # Admin eines setzt.
        user_id = create_user(
            conn,
            _free_username(conn, who.username),
            secrets.token_urlsafe(32),
            display_name=who.name,
            email=who.email,
        )
        row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        log.warning("User %s created from single sign-on.", row["username"])
        log_activity(conn, row, "user_created_sso", row["username"], f"subject {who.sub}"[:200])
    if not row["enabled"]:
        raise OidcError(DISABLED)
    updates = {"oidc_sub": who.sub}
    if who.name and not row["display_name"]:
        updates["display_name"] = who.name
    if who.email and not row["email"]:
        updates["email"] = who.email
    # Admin-Gruppe macht zum Admin; entzogen wird das Recht nie automatisch, damit sich
    # niemand aussperrt.
    if cfg.oidc_admin_group and cfg.oidc_admin_group in who.groups:
        updates["is_admin"] = 1
    sets = ", ".join(f"{k} = ?" for k in updates)
    conn.execute(f"UPDATE users SET {sets} WHERE id = ?", (*updates.values(), row["id"]))
    return conn.execute("SELECT * FROM users WHERE id = ?", (row["id"],)).fetchone()


def _free_username(conn: sqlite3.Connection, wanted: str) -> str:
    name, n = wanted, 1
    while conn.execute("SELECT 1 FROM users WHERE username = ?", (name,)).fetchone():
        n += 1
        name = f"{wanted[:60]}{n}"
    return name
