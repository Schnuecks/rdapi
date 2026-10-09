"""Härtung aus 0.7.0: Grenzen, Header, Cookie, Aktivität, verschlüsselte TOTP-Schlüssel."""

from __future__ import annotations

import re
import time
from dataclasses import replace

from conftest import ADMIN_PW, USER_PW, web_login
from fastapi.testclient import TestClient

from rdapi import secretbox, totp
from rdapi.db import connect
from rdapi.main import MAX_REQUEST, checked_oidc, create_app
from rdapi.security import create_user


def test_too_large_requests_are_rejected(client):
    big = "x" * (MAX_REQUEST + 1)
    assert client.post("/login", data={"username": big}).status_code == 413
    assert client.post("/api/heartbeat", content=big).status_code == 413


def test_pages_are_not_cached_but_static_files_are(client):
    web_login(client)
    assert client.get("/account").headers["cache-control"] == "no-store"
    assert client.get("/api/login-options").headers["cache-control"] == "no-store"
    assert "cache-control" not in client.get("/static/style.css").headers


def test_hsts_and_host_cookie_over_https(cfg):
    app = create_app(replace(cfg, cookie_secure=None))
    with TestClient(app, base_url="https://testserver") as c:
        resp = c.post(
            "/login", data={"username": "admin", "password": ADMIN_PW}, follow_redirects=False
        )
        assert resp.headers["strict-transport-security"].startswith("max-age=")
        cookie = resp.headers["set-cookie"]
        assert cookie.startswith("__Host-rdapi_session=")
        assert "Secure" in cookie and "Path=/" in cookie
        assert c.get("/account").status_code == 200
    with TestClient(app) as c:
        assert "strict-transport-security" not in c.get("/login").headers


def test_starting_passkey_sign_ins_is_limited(client):
    codes = [client.post("/login/passkey/options").status_code for _ in range(31)]
    assert codes[:30] == [200] * 30
    assert codes[30] == 429


def test_device_reports_are_limited(cfg):
    app = create_app(replace(cfg, device_requests_per_minute=3))
    with TestClient(app) as c:
        codes = [c.post("/api/heartbeat", json={"id": "1"}).status_code for _ in range(4)]
        assert codes == [200, 200, 200, 429]


def test_blocked_attempts_are_logged_once_per_minute(client, db):
    for _ in range(12):
        client.post("/api/login", json={"username": "alice", "password": "falsch"})
    blocked = db.execute(
        "SELECT COUNT(*) FROM login_events WHERE detail LIKE 'blocked%'"
    ).fetchone()[0]
    assert blocked == 1


def test_activity_is_recorded_and_admin_only(client, db):
    csrf = web_login(client)
    client.post("/users/new", data={"csrf": csrf, "username": "bob", "password": "bob-passwort-1"})
    bob = db.execute("SELECT id FROM users WHERE username = 'bob'").fetchone()[0]
    client.post(
        f"/users/{bob}",
        data={"csrf": csrf, "is_admin": "1", "enabled": "1", "password": "neues-passwort-1"},
    )
    client.post("/backups/new", data={"csrf": csrf})
    name = re.search(r'href="/backups/(rdapi-[\d-]+\.sqlite3)"', client.get("/backups").text)
    client.get(f"/backups/{name.group(1)}")
    client.post(f"/users/{bob}/delete", data={"csrf": csrf})

    rows = db.execute("SELECT actor, action, target, detail FROM activity ORDER BY id").fetchall()
    assert [r["action"] for r in rows] == [
        "user_created",
        "user_changed",
        "backup_created",
        "backup_downloaded",
        "user_deleted",
    ]
    assert rows[1]["detail"] == "password set, admin on"
    assert all(r["actor"] == "admin" for r in rows)
    page = client.get("/activity").text
    assert "Created a user" in page and "bob" in page

    client.cookies.clear()
    web_login(client, "alice", USER_PW)
    assert client.get("/activity").status_code == 403


def test_own_security_changes_are_recorded(client, db):
    csrf = web_login(client, "alice", USER_PW)
    client.post(
        "/account/password",
        data={
            "csrf": csrf,
            "old": USER_PW,
            "new": "anderes-passwort-1",
            "new2": "anderes-passwort-1",
        },
    )
    assert tuple(db.execute("SELECT action, actor FROM activity").fetchone()) == (
        "password_changed",
        "alice",
    )


def _enable_totp(client, csrf: str) -> str:
    page = client.post("/account/2fa/start", data={"csrf": csrf}).text
    secret = re.search(r'<code class="secret">([A-Z2-7 ]+)</code>', page).group(1).replace(" ", "")
    code = totp._code(secret, int(time.time() // totp.STEP))
    client.post("/account/2fa/confirm", data={"csrf": csrf, "code": code})
    return secret


def _app_login_with_code(c: TestClient, secret: str, db) -> int:
    db.execute("UPDATE users SET totp_last_step = 0")
    first = c.post("/api/login", json={"username": "alice", "password": USER_PW}).json()
    code = totp._code(secret, int(time.time() // totp.STEP))
    return c.post(
        "/api/login",
        json={
            "username": "alice",
            "type": "email_code",
            "secret": first["secret"],
            "tfaCode": code,
        },
    ).status_code


def test_totp_secret_is_encrypted_with_secret_key(cfg, db):
    app = create_app(replace(cfg, secret_key="ein-langes-geheimnis"))
    conn = connect(cfg.db_path)
    create_user(conn, "alice", USER_PW)
    conn.close()
    with TestClient(app) as c:
        secret = _enable_totp(c, web_login(c, "alice", USER_PW))
        stored = db.execute("SELECT totp_secret FROM users WHERE username = 'alice'").fetchone()[0]
        assert stored.startswith(secretbox.PREFIX)
        assert secret not in stored
        assert _app_login_with_code(c, secret, db) == 200


def test_existing_secrets_are_encrypted_on_start(cfg, db, caplog):
    app = create_app(cfg)
    conn = connect(cfg.db_path)
    create_user(conn, "alice", USER_PW)
    conn.close()
    with TestClient(app) as c:
        secret = _enable_totp(c, web_login(c, "alice", USER_PW))
    assert (
        db.execute("SELECT totp_secret FROM users WHERE username = 'alice'").fetchone()[0] == secret
    )

    with TestClient(create_app(replace(cfg, secret_key="neu-gesetzt-123"))) as c:
        stored = db.execute("SELECT totp_secret FROM users WHERE username = 'alice'").fetchone()[0]
        assert stored.startswith(secretbox.PREFIX)
        assert _app_login_with_code(c, secret, db) == 200

    # Falscher Schlüssel: deutliche Meldung, Codes gehen nicht.
    with TestClient(create_app(replace(cfg, secret_key="falscher-schluessel"))) as c:
        assert "Cannot decrypt the two-factor key" in caplog.text
        assert _app_login_with_code(c, secret, db) == 401


def test_oidc_issuer_must_use_https(cfg):
    assert checked_oidc(replace(cfg, oidc_issuer="http://auth.example.com")).oidc_issuer == ""
    assert checked_oidc(replace(cfg, oidc_issuer="https://auth.example.com")).oidc_issuer
    assert checked_oidc(replace(cfg, oidc_issuer="http://localhost:9091")).oidc_issuer


def test_forms_may_redirect_to_a_proxy_login_page(client):
    # Hinter einer Anmeldeseite (z. B. Authelia) leitet der Proxy Formulare dorthin um.
    csp = client.get("/login").headers["content-security-policy"]
    assert "form-action 'self' https:;" in csp


def test_get_logout_offers_sign_out_or_goes_to_login(client):
    assert client.get("/logout", follow_redirects=False).headers["location"] == "/login"
    web_login(client)
    page = client.get("/logout")
    assert page.status_code == 200
    assert 'action="/logout"' in page.text
    csrf = re.search(r'name="csrf" value="([^"]+)"', page.text).group(1)
    client.post("/logout", data={"csrf": csrf})
    assert client.get("/account", follow_redirects=False).status_code == 303


def test_get_on_form_only_address_goes_home(client):
    web_login(client)
    resp = client.get("/account/password", follow_redirects=False)
    assert resp.status_code == 303 and resp.headers["location"] == "/"
    assert client.get("/api/login", follow_redirects=False).status_code == 405
