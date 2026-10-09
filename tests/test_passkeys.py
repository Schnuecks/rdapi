"""Passkeys und Sicherheitsschlüssel (WebAuthn) mit nachgestelltem Authenticator."""

from __future__ import annotations

import base64
import hashlib
import json
import re
import secrets
import struct

import cbor2
from conftest import ADMIN_PW, USER_PW, web_login
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

RP_ID = "testserver"
ORIGIN = "http://testserver"


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


class Authenticator:
    """Ein Passkey: erzeugt Schlüssel und unterschreibt wie ein echtes Gerät."""

    def __init__(self) -> None:
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.cred_id = secrets.token_bytes(16)
        self.count = 0

    def _cose(self) -> bytes:
        nums = self.key.public_key().public_numbers()
        return cbor2.dumps(
            {1: 2, 3: -7, -1: 1, -2: nums.x.to_bytes(32, "big"), -3: nums.y.to_bytes(32, "big")}
        )

    def _client_data(self, kind: str, challenge: str, origin: str) -> bytes:
        return json.dumps({"type": kind, "challenge": challenge, "origin": origin}).encode()

    def create(self, options: dict, origin: str = ORIGIN) -> dict:
        client = self._client_data("webauthn.create", options["challenge"], origin)
        auth = (
            hashlib.sha256(options["rp"]["id"].encode()).digest()
            + bytes([0x45])  # Anwesenheit, Prüfung der Person, Schlüsseldaten
            + struct.pack(">I", 0)
            + bytes(16)
            + struct.pack(">H", len(self.cred_id))
            + self.cred_id
            + self._cose()
        )
        att = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth})
        return {
            "id": b64(self.cred_id),
            "rawId": b64(self.cred_id),
            "type": "public-key",
            "response": {"clientDataJSON": b64(client), "attestationObject": b64(att)},
            "clientExtensionResults": {},
        }

    def get(self, options: dict, origin: str = ORIGIN, verified: bool = True) -> dict:
        self.count += 1
        client = self._client_data("webauthn.get", options["challenge"], origin)
        auth = (
            hashlib.sha256(options["rpId"].encode()).digest()
            + bytes([0x05 if verified else 0x01])
            + struct.pack(">I", self.count)
        )
        sig = self.key.sign(auth + hashlib.sha256(client).digest(), ec.ECDSA(hashes.SHA256()))
        return {
            "id": b64(self.cred_id),
            "rawId": b64(self.cred_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": b64(client),
                "authenticatorData": b64(auth),
                "signature": b64(sig),
            },
            "clientExtensionResults": {},
        }


def add_passkey(client, csrf: str, name: str = "Laptop") -> tuple[Authenticator, object]:
    key = Authenticator()
    opts = client.post("/account/passkeys/options", json={"csrf": csrf}).json()
    assert opts["options"]["rp"]["id"] == RP_ID
    resp = client.post(
        "/account/passkeys",
        json={
            "csrf": csrf,
            "token": opts["token"],
            "name": name,
            "credential": key.create(opts["options"]),
        },
    )
    return key, resp


def passkey_login(client, key: Authenticator, **kwargs):
    opts = client.post("/login/passkey/options").json()
    assert opts["options"].get("userVerification") == "required"
    return client.post(
        "/login/passkey",
        json={
            "token": opts["token"],
            "next": "/history",
            "credential": key.get(opts["options"], **kwargs),
        },
        follow_redirects=False,
    )


def test_add_passkey_shows_recovery_codes_once(client, db):
    csrf = web_login(client, "alice", USER_PW)
    _, first = add_passkey(client, csrf)
    assert first.status_code == 200
    assert len(re.findall(r"<li><code>[A-Z2-9]{4}-[A-Z2-9]{4}</code></li>", first.text)) == 8
    _, second = add_passkey(client, csrf, "Schlüssel")
    assert str(second.url).endswith("/account?ok=passkey")
    assert db.execute("SELECT COUNT(*) FROM passkeys").fetchone()[0] == 2
    assert "Schlüssel" in client.get("/account").text


def test_login_with_passkey_without_password(client, db):
    assert "data-passkey-login" not in client.get("/login").text  # noch keine Passkeys
    csrf = web_login(client, "alice", USER_PW)
    key, _ = add_passkey(client, csrf)
    client.cookies.clear()
    assert "data-passkey-login" in client.get("/login").text

    resp = passkey_login(client, key)
    assert resp.status_code == 303
    assert resp.headers["location"] == "/history"
    assert client.get("/account").status_code == 200
    row = db.execute("SELECT sign_count, last_used_at FROM passkeys").fetchone()
    assert row["sign_count"] == 1 and row["last_used_at"]


def test_passwordless_login_needs_user_verification(client):
    csrf = web_login(client, "alice", USER_PW)
    key, _ = add_passkey(client, csrf)
    client.cookies.clear()
    assert passkey_login(client, key, verified=False).status_code == 400


def test_wrong_origin_and_replay_are_rejected(client):
    csrf = web_login(client, "alice", USER_PW)
    key, _ = add_passkey(client, csrf)
    client.cookies.clear()
    assert passkey_login(client, key, origin="https://evil.example").status_code == 400

    opts = client.post("/login/passkey/options").json()
    body = {"token": opts["token"], "credential": key.get(opts["options"])}
    assert client.post("/login/passkey", json=body, follow_redirects=False).status_code == 303
    client.cookies.clear()
    again = client.post("/login/passkey", json=body)
    assert again.status_code == 400
    assert "expired" in again.json()["error"]


def test_unknown_passkey_is_rejected(client):
    opts = client.post("/login/passkey/options").json()
    resp = client.post(
        "/login/passkey",
        json={"token": opts["token"], "credential": Authenticator().get(opts["options"])},
    )
    assert resp.status_code == 400
    assert "not known" in resp.json()["error"]


def test_password_login_then_asks_for_passkey(client):
    csrf = web_login(client, "alice", USER_PW)
    key, _ = add_passkey(client, csrf)
    client.cookies.clear()

    page = client.post("/login", data={"username": "alice", "password": USER_PW, "next": "/"})
    assert page.status_code == 200
    assert "data-passkey-second" in page.text
    pending = re.search(r'data-pending="([^"]+)"', page.text).group(1)
    assert client.get("/account", follow_redirects=False).status_code == 303

    opts = client.post("/login/code/passkey/options", json={"pending": pending}).json()
    assert [c["id"] for c in opts["options"]["allowCredentials"]] == [b64(key.cred_id)]
    resp = client.post(
        "/login/code/passkey",
        json={"pending": pending, "token": opts["token"], "credential": key.get(opts["options"])},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert client.get("/account").status_code == 200


def test_second_factor_rejects_someone_elses_passkey(client):
    csrf = web_login(client, "admin", ADMIN_PW)
    admin_key, _ = add_passkey(client, csrf)
    client.cookies.clear()
    csrf = web_login(client, "alice", USER_PW)
    add_passkey(client, csrf)
    client.cookies.clear()

    page = client.post("/login", data={"username": "alice", "password": USER_PW})
    pending = re.search(r'data-pending="([^"]+)"', page.text).group(1)
    opts = client.post("/login/code/passkey/options", json={"pending": pending}).json()
    resp = client.post(
        "/login/code/passkey",
        json={
            "pending": pending,
            "token": opts["token"],
            "credential": admin_key.get(opts["options"]),
        },
    )
    assert resp.status_code == 400


def test_recovery_code_works_without_passkey(client):
    csrf = web_login(client, "alice", USER_PW)
    _, page = add_passkey(client, csrf)
    code = re.search(r"<li><code>([A-Z2-9]{4}-[A-Z2-9]{4})</code></li>", page.text).group(1)
    client.cookies.clear()
    step = client.post("/login", data={"username": "alice", "password": USER_PW})
    assert "Recovery code" in step.text
    pending = re.search(r'name="pending" value="([^"]+)"', step.text).group(1)
    resp = client.post(
        "/login/code", data={"pending": pending, "code": code, "next": "/"}, follow_redirects=False
    )
    assert resp.status_code == 303


def test_removing_last_passkey_turns_second_factor_off(client, db):
    csrf = web_login(client, "alice", USER_PW)
    add_passkey(client, csrf)
    key_id = db.execute("SELECT id FROM passkeys").fetchone()[0]
    client.post(f"/account/passkeys/{key_id}/delete", data={"csrf": csrf})
    assert db.execute("SELECT COUNT(*) FROM recovery_codes").fetchone()[0] == 0
    client.cookies.clear()
    resp = client.post(
        "/login", data={"username": "alice", "password": USER_PW}, follow_redirects=False
    )
    assert resp.status_code == 303


def test_app_login_is_unaffected_by_passkeys(client):
    csrf = web_login(client, "alice", USER_PW)
    add_passkey(client, csrf)
    resp = client.post("/api/login", json={"username": "alice", "password": USER_PW})
    assert resp.json()["type"] == "access_token"


def test_admin_reset_removes_passkeys(client, db):
    csrf = web_login(client, "alice", USER_PW)
    add_passkey(client, csrf)
    client.cookies.clear()
    admin_csrf = web_login(client, "admin", ADMIN_PW)
    alice_id = db.execute("SELECT id FROM users WHERE username = 'alice'").fetchone()[0]
    assert "Passkeys" in client.get(f"/users/{alice_id}").text
    client.post(f"/users/{alice_id}/2fa/reset", data={"csrf": admin_csrf})
    assert db.execute("SELECT COUNT(*) FROM passkeys").fetchone()[0] == 0
    assert db.execute("SELECT COUNT(*) FROM recovery_codes").fetchone()[0] == 0


def test_register_needs_csrf(client):
    web_login(client, "alice", USER_PW)
    assert client.post("/account/passkeys/options", json={"csrf": "falsch"}).status_code == 403
