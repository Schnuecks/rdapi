"""Zwei-Faktor-Anmeldung in Weboberfläche und App."""

from __future__ import annotations

import re
import time

from conftest import ADMIN_PW, USER_PW, web_login

from rdapi import totp


def code_for(secret: str, offset: int = 0) -> str:
    return totp._code(secret, int(time.time() // totp.STEP) + offset)


def enable_2fa(client, csrf: str) -> tuple[str, list[str]]:
    """Schaltet 2FA für den angemeldeten Benutzer ein; liefert Schlüssel und Codes."""
    page = client.post("/account/2fa/start", data={"csrf": csrf}).text
    assert "<svg" in page
    secret = re.search(r'<code class="secret">([A-Z2-7 ]+)</code>', page).group(1)
    secret = secret.replace(" ", "")
    wrong = client.post("/account/2fa/confirm", data={"csrf": csrf, "code": "000000"})
    assert wrong.status_code == 400
    page = client.post("/account/2fa/confirm", data={"csrf": csrf, "code": code_for(secret)}).text
    codes = re.findall(r"<li><code>([A-Z2-9]{4}-[A-Z2-9]{4})</code></li>", page)
    assert len(codes) == 8
    return secret, codes


def sign_out(client, csrf: str) -> None:
    client.post("/logout", data={"csrf": csrf})


def password_step(client, username="alice", password=USER_PW) -> str:
    resp = client.post("/login", data={"username": username, "password": password, "next": "/"})
    assert resp.status_code == 200
    return re.search(r'name="pending" value="([^"]+)"', resp.text).group(1)


def test_totp_matches_rfc_6238():
    import base64

    secret = base64.b32encode(b"12345678901234567890").decode()
    assert totp.matching_step(secret, "287082", at=59) == 1
    assert totp.matching_step(secret, "287083", at=59) is None


def test_web_login_with_code_and_recovery_code(client, db):
    csrf = web_login(client, "alice", USER_PW)
    secret, codes = enable_2fa(client, csrf)
    sign_out(client, csrf)

    # Passwort allein reicht nicht mehr.
    pending = password_step(client)
    assert client.get("/account", follow_redirects=False).status_code == 303
    wrong = client.post("/login/code", data={"pending": pending, "code": "123456", "next": "/"})
    assert wrong.status_code == 401
    db.execute("UPDATE users SET totp_last_step = 0")
    ok = client.post(
        "/login/code",
        data={"pending": pending, "code": code_for(secret), "next": "/"},
        follow_redirects=False,
    )
    assert ok.status_code == 303
    assert client.get("/account").status_code == 200
    csrf = re.search(r'name="csrf" value="([^"]+)"', client.get("/account").text).group(1)
    sign_out(client, csrf)

    # Wiederherstellungscode funktioniert genau einmal.
    pending = password_step(client)
    used = codes[0].lower()
    ok = client.post(
        "/login/code", data={"pending": pending, "code": used, "next": "/"}, follow_redirects=False
    )
    assert ok.status_code == 303
    csrf = re.search(r'name="csrf" value="([^"]+)"', client.get("/account").text).group(1)
    sign_out(client, csrf)
    pending = password_step(client)
    again = client.post("/login/code", data={"pending": pending, "code": used, "next": "/"})
    assert again.status_code == 401


def test_same_code_is_accepted_only_once(client, db):
    csrf = web_login(client, "alice", USER_PW)
    secret, _ = enable_2fa(client, csrf)
    sign_out(client, csrf)
    db.execute("UPDATE users SET totp_last_step = 0")
    code = code_for(secret)
    pending = password_step(client)
    first = client.post("/login/code", data={"pending": pending, "code": code, "next": "/"})
    assert first.status_code == 200  # Weiterleitung auf die Geräteliste
    client.cookies.clear()
    pending = password_step(client)
    second = client.post("/login/code", data={"pending": pending, "code": code, "next": "/"})
    assert second.status_code == 401


def test_pending_login_expires_after_too_many_attempts(client):
    csrf = web_login(client, "alice", USER_PW)
    enable_2fa(client, csrf)
    sign_out(client, csrf)
    pending = password_step(client)
    for _ in range(5):
        client.post("/login/code", data={"pending": pending, "code": "000000", "next": "/"})
    resp = client.post("/login/code", data={"pending": pending, "code": "000000", "next": "/"})
    assert "expired" in resp.text or resp.status_code == 429


def test_app_login_with_two_factor(client, db):
    csrf = web_login(client, "alice", USER_PW)
    secret, _ = enable_2fa(client, csrf)
    db.execute("UPDATE users SET totp_last_step = 0")
    login = {"username": "alice", "password": USER_PW, "id": "123", "uuid": "u", "type": "account"}
    first = client.post("/api/login", json=login).json()
    assert first["type"] == "email_check"
    assert first["tfa_type"] == "tfa_check"
    assert first["secret"] and "access_token" not in first

    # So schickt die App den zweiten Schritt.
    second = {
        "username": "alice",
        "id": "123",
        "uuid": "u",
        "autoLogin": True,
        "type": "email_code",
        "secret": first["secret"],
        "verificationCode": "000000",
        "tfaCode": "000000",
    }
    assert client.post("/api/login", json=second).status_code == 401
    code = code_for(secret)
    resp = client.post("/api/login", json={**second, "verificationCode": code, "tfaCode": code})
    assert resp.status_code == 200
    token = resp.json()["access_token"]
    me = client.post("/api/currentUser", headers={"Authorization": f"Bearer {token}"}, json={})
    assert me.json()["name"] == "alice"
    # Geheimnis ist verbraucht.
    reuse = client.post("/api/login", json={**second, "tfaCode": code_for(secret, 1)})
    assert reuse.status_code == 401


def test_turn_off_and_admin_reset(client, db):
    csrf = web_login(client, "alice", USER_PW)
    secret, codes = enable_2fa(client, csrf)
    bad = client.post(
        "/account/2fa/disable", data={"csrf": csrf, "password": "falsch", "code": codes[0]}
    )
    assert bad.status_code == 400
    ok = client.post(
        "/account/2fa/disable", data={"csrf": csrf, "password": USER_PW, "code": codes[0]}
    )
    assert ok.status_code == 200
    assert db.execute("SELECT totp_enabled FROM users WHERE username = 'alice'").fetchone()[0] == 0

    enable_2fa(client, csrf)
    sign_out(client, csrf)
    admin_csrf = web_login(client, "admin", ADMIN_PW)
    alice_id = db.execute("SELECT id FROM users WHERE username = 'alice'").fetchone()[0]
    client.post(f"/users/{alice_id}/2fa/reset", data={"csrf": admin_csrf})
    row = db.execute("SELECT totp_enabled, totp_secret FROM users WHERE id = ?", (alice_id,))
    assert tuple(row.fetchone()) == (0, "")
    assert db.execute("SELECT COUNT(*) FROM recovery_codes").fetchone()[0] == 0


def test_new_recovery_codes_replace_old_ones(client, db):
    csrf = web_login(client, "alice", USER_PW)
    secret, codes = enable_2fa(client, csrf)
    page = client.post(
        "/account/2fa/recovery", data={"csrf": csrf, "password": USER_PW, "code": codes[1]}
    ).text
    new_codes = re.findall(r"<li><code>([A-Z2-9]{4}-[A-Z2-9]{4})</code></li>", page)
    assert len(new_codes) == 8 and not set(new_codes) & set(codes)
    assert db.execute("SELECT COUNT(*) FROM recovery_codes").fetchone()[0] == 8
