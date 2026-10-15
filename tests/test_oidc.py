"""Anmeldung über einen OpenID-Connect-Anbieter, mit nachgestelltem Anbieter."""

from __future__ import annotations

import base64
import json
import re
import time
from dataclasses import replace
from urllib.parse import parse_qs, urlparse

import pytest
from conftest import USER_PW, web_login
from fastapi.testclient import TestClient

from rdapi import oidc
from rdapi.main import create_app

ISSUER = "https://auth.example.com"


def jwt(claims: dict) -> str:
    def part(data: dict) -> str:
        return base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip("=")

    return f"{part({'alg': 'RS256'})}.{part(claims)}.c2ln"


class FakeProvider:
    """Antwortet wie ein Anbieter; `who` bestimmt, wer sich dort anmeldet."""

    def __init__(self) -> None:
        self.who = {
            "sub": "u-1",
            "preferred_username": "alice",
            "email": "alice@example.com",
            "email_verified": True,
        }
        self.nonces: dict[str, str] = {}  # Code beim Anbieter -> Nonce
        self.id_token_changes: dict = {}
        self.last_token_request: dict = {}

    def authorize(self, url: str) -> str:
        """Was der Browser nach der Anmeldung beim Anbieter aufruft (Rücksprung)."""
        q = {k: v[0] for k, v in parse_qs(urlparse(url).query).items()}
        assert q["code_challenge_method"] == "S256" and q["code_challenge"]
        code = f"code-{len(self.nonces)}"
        self.nonces[code] = q["nonce"]
        return f"{urlparse(q['redirect_uri']).path}?code={code}&state={q['state']}"

    def http_json(self, url: str, data: dict | None = None, token: str = "") -> dict:
        if url.endswith("/.well-known/openid-configuration"):
            return {
                "issuer": ISSUER,
                "authorization_endpoint": f"{ISSUER}/authorize",
                "token_endpoint": f"{ISSUER}/token",
                "userinfo_endpoint": f"{ISSUER}/userinfo",
            }
        if url.endswith("/token"):
            self.last_token_request = data
            claims = {
                "iss": ISSUER,
                "aud": ["rdapi"],
                "exp": int(time.time()) + 300,
                "nonce": self.nonces[data["code"]],
                "sub": self.who["sub"],
                **self.id_token_changes,
            }
            return {"id_token": jwt(claims), "access_token": "at"}
        if url.endswith("/userinfo"):
            assert token == "at"
            return dict(self.who)
        raise AssertionError(url)


@pytest.fixture
def provider(monkeypatch) -> FakeProvider:
    fake = FakeProvider()
    monkeypatch.setattr(oidc, "_http_json", fake.http_json)
    oidc._discovery.clear()
    return fake


@pytest.fixture
def sso_cfg(cfg):
    return replace(
        cfg,
        oidc_issuer=ISSUER,
        oidc_client_id="rdapi",
        oidc_client_secret="geheim",
        oidc_name="Authelia",
        oidc_admin_group="admins",
    )


@pytest.fixture
def sso(sso_cfg, provider):
    from rdapi.db import connect
    from rdapi.security import create_user

    app = create_app(sso_cfg)
    conn = connect(sso_cfg.db_path)
    create_user(conn, "alice", USER_PW, email="alice@example.com")
    conn.close()
    with TestClient(app) as c:
        yield c


def web_sso_login(client: TestClient, provider: FakeProvider):
    start = client.get("/login/oidc?next=/history", follow_redirects=False)
    assert start.status_code == 303
    back = provider.authorize(start.headers["location"])
    return client.get(back, follow_redirects=False)


def test_without_issuer_nothing_changes(client):
    assert client.get("/api/login-options").json() == []
    assert "/login/oidc" not in client.get("/login").text
    assert client.get("/login/oidc", follow_redirects=False).headers["location"] == "/login"


def test_login_options_and_button(sso):
    assert sso.get("/api/login-options").json() == ["oidc/Authelia"]
    assert "Sign in with Authelia" in sso.get("/login").text


def test_web_login_links_existing_user(sso, provider, db):
    resp = web_sso_login(sso, provider)
    assert resp.status_code == 303
    assert resp.headers["location"] == "/history"
    assert provider.last_token_request["code_verifier"]
    assert provider.last_token_request["client_secret"] == "geheim"
    row = db.execute("SELECT oidc_sub, email FROM users WHERE username = 'alice'").fetchone()
    assert tuple(row) == ("u-1", "alice@example.com")
    assert sso.get("/account").status_code == 200
    # Die normale Anmeldung mit Passwort geht weiterhin.
    sso.cookies.clear()
    resp = sso.post(
        "/login", data={"username": "alice", "password": USER_PW}, follow_redirects=False
    )
    assert resp.status_code == 303


def test_new_user_is_created_and_admin_group_applies(sso, provider, db):
    provider.who = {
        "sub": "u-2",
        "preferred_username": "bob",
        "name": "Bob Example",
        "email": "bob@example.com",
        "email_verified": True,
        "groups": ["admins", "family"],
    }
    assert web_sso_login(sso, provider).status_code == 303
    row = db.execute("SELECT * FROM users WHERE username = 'bob'").fetchone()
    assert row["display_name"] == "Bob Example"
    assert row["is_admin"] == 1
    assert row["oidc_sub"] == "u-2"
    # Zweite Anmeldung: dasselbe Konto, auch wenn sich der Name beim Anbieter ändert.
    sso.cookies.clear()
    provider.who = {**provider.who, "preferred_username": "robert"}
    web_sso_login(sso, provider)
    assert db.execute("SELECT COUNT(*) FROM users WHERE oidc_sub = 'u-2'").fetchone()[0] == 1


def test_no_new_users_when_turned_off(sso_cfg, provider, db):
    app = create_app(replace(sso_cfg, oidc_create_users=False))
    provider.who = {"sub": "u-3", "preferred_username": "carol"}
    with TestClient(app) as c:
        resp = web_sso_login(c, provider)
        assert resp.status_code == 401
        assert "no account" in resp.text
    assert db.execute("SELECT COUNT(*) FROM users WHERE username = 'carol'").fetchone()[0] == 0


def test_disabled_user_cannot_sign_in(sso, provider, db):
    db.execute("UPDATE users SET enabled = 0 WHERE username = 'alice'")
    assert web_sso_login(sso, provider).status_code == 401


@pytest.mark.parametrize(
    "change",
    [{"iss": "https://evil.example"}, {"aud": "other"}, {"exp": 1}, {"nonce": "falsch"}],
)
def test_bad_id_token_is_rejected(sso, provider, change):
    provider.id_token_changes = change
    resp = web_sso_login(sso, provider)
    assert resp.status_code == 401
    assert sso.get("/account", follow_redirects=False).status_code == 303


def test_callback_needs_the_same_browser(sso, provider):
    start = sso.get("/login/oidc", follow_redirects=False)
    back = provider.authorize(start.headers["location"])
    sso.cookies.clear()  # anderer Browser
    assert sso.get(back, follow_redirects=False).status_code == 401


def test_state_works_only_once(sso, provider):
    start = sso.get("/login/oidc", follow_redirects=False)
    back = provider.authorize(start.headers["location"])
    assert sso.get(back, follow_redirects=False).status_code == 303
    assert sso.get(back, follow_redirects=False).status_code == 401


def link_with_provider(client: TestClient, provider: FakeProvider, csrf: str):
    start = client.post("/account/sso/link", data={"csrf": csrf}, follow_redirects=False)
    assert start.status_code == 303
    return client.get(provider.authorize(start.headers["location"]), follow_redirects=False)


def test_admin_is_never_linked_automatically_but_can_link_on_the_account_page(sso, provider, db):
    db.execute("UPDATE users SET email = 'admin@example.com' WHERE username = 'admin'")
    provider.who = {
        "sub": "u-9",
        "preferred_username": "admin",
        "email": "admin@example.com",
        "email_verified": True,
        "groups": [],
    }
    # Bestätigte E-Mail-Adresse eines Admins: kein automatisches Verknüpfen.
    web_sso_login(sso, provider)
    assert db.execute("SELECT oidc_sub FROM users WHERE username = 'admin'").fetchone()[0] == ""
    db.execute("DELETE FROM users WHERE oidc_sub = 'u-9'")
    sso.cookies.clear()

    # Der Admin meldet sich mit Passwort an und verknüpft selbst.
    csrf = web_login(sso)
    assert "Link with Authelia" in sso.get("/account").text
    done = link_with_provider(sso, provider, csrf)
    assert done.status_code == 200 and "is now linked" in done.text
    assert db.execute("SELECT oidc_sub FROM users WHERE username = 'admin'").fetchone()[0] == "u-9"
    assert "Linked the account for single sign-on" in sso.get("/activity").text

    # Ab jetzt per Anbieter; Admin-Rechte werden nie automatisch entzogen.
    sso.cookies.clear()
    assert web_sso_login(sso, provider).status_code == 303
    assert db.execute("SELECT is_admin FROM users WHERE username = 'admin'").fetchone()[0] == 1


def test_no_account_for_an_admin_email_when_creating_is_off(sso_cfg, provider, db):
    app = create_app(replace(sso_cfg, oidc_create_users=False))
    db.execute("UPDATE users SET email = 'admin@example.com' WHERE username = 'admin'")
    provider.who = {"sub": "u-8", "email": "admin@example.com", "email_verified": True}
    with TestClient(app) as c:
        resp = web_sso_login(c, provider)
        assert resp.status_code == 401 and "no account" in resp.text
    assert db.execute("SELECT oidc_sub FROM users WHERE username = 'admin'").fetchone()[0] == ""


def test_link_fails_if_the_provider_account_is_taken(sso, provider, db):
    db.execute("UPDATE users SET oidc_sub = 'u-1' WHERE username = 'alice'")
    csrf = web_login(sso)
    done = link_with_provider(sso, provider, csrf)
    assert done.status_code == 400 and "already linked to another account" in done.text
    assert db.execute("SELECT oidc_sub FROM users WHERE username = 'admin'").fetchone()[0] == ""


def test_link_needs_csrf_and_the_same_browser(sso, provider, db):
    csrf = web_login(sso)
    assert sso.post("/account/sso/link", data={"csrf": "falsch"}).status_code == 403
    start = sso.post("/account/sso/link", data={"csrf": csrf}, follow_redirects=False)
    back = provider.authorize(start.headers["location"])
    sso.cookies.delete("rdapi_oidc")
    assert sso.get(back, follow_redirects=False).status_code == 401
    assert db.execute("SELECT oidc_sub FROM users WHERE username = 'admin'").fetchone()[0] == ""


def test_app_login_with_provider(sso, provider, db):
    device = {"id": "123123123", "uuid": "dXVpZA==", "deviceInfo": {"name": "Laptop"}}
    resp = sso.post("/api/oidc/auth", json={"op": "Authelia", **device}).json()
    code, url = resp["code"], resp["url"]
    assert url.startswith(f"{ISSUER}/authorize?")
    query = {"code": code, "id": "123123123", "uuid": "dXVpZA=="}

    # Noch nicht angemeldet: die App soll weiter nachfragen.
    assert sso.get("/api/oidc/auth-query", params=query).json() == {
        "error": "No authed oidc is found"
    }

    # Im Browser beim Anbieter anmelden, dann bestätigen.
    page = sso.get(provider.authorize(url))
    assert page.status_code == 200
    assert "123123123" in page.text and "alice" in page.text
    assert sso.get("/api/oidc/auth-query", params=query).json()["error"] == (
        "No authed oidc is found"
    )
    confirm = re.search(r'name="confirm" value="([^"]+)"', page.text).group(1)
    done = sso.post("/oidc/confirm", data={"confirm": confirm, "action": "allow"})
    assert "close this window" in done.text

    result = sso.get("/api/oidc/auth-query", params=query).json()
    assert result["type"] == "access_token"
    assert result["user"]["name"] == "alice"
    me = sso.post(
        "/api/currentUser", headers={"Authorization": f"Bearer {result['access_token']}"}, json={}
    )
    assert me.json()["name"] == "alice"
    owner = db.execute("SELECT user_id FROM devices WHERE id = '123123123'").fetchone()[0]
    assert owner == db.execute("SELECT id FROM users WHERE username = 'alice'").fetchone()[0]
    # Der Code ist verbraucht.
    again = sso.get("/api/oidc/auth-query", params=query).json()
    assert "expired" in again["error"]


def test_app_login_can_be_cancelled_and_needs_matching_device(sso, provider):
    resp = sso.post("/api/oidc/auth", json={"op": "Authelia", "id": "1", "uuid": "u"}).json()
    page = sso.get(provider.authorize(resp["url"]))
    confirm = re.search(r'name="confirm" value="([^"]+)"', page.text).group(1)
    wrong_device = {"code": resp["code"], "id": "2", "uuid": "u"}
    assert "expired" in sso.get("/api/oidc/auth-query", params=wrong_device).json()["error"]
    sso.post("/oidc/confirm", data={"confirm": confirm, "action": "cancel"})
    query = {"code": resp["code"], "id": "1", "uuid": "u"}
    assert "expired" in sso.get("/api/oidc/auth-query", params=query).json()["error"]


def test_app_oidc_not_set_up(client):
    assert client.post("/api/oidc/auth", json={"op": "x"}).status_code == 400


def test_username_alone_never_takes_over_an_account(sso, provider, db):
    """Wer sich beim Anbieter „admin“ nennt, bekommt nicht das lokale Admin-Konto."""
    provider.who = {"sub": "attacker", "preferred_username": "admin"}
    assert web_sso_login(sso, provider).status_code == 303
    admin = db.execute("SELECT oidc_sub, is_admin FROM users WHERE username = 'admin'").fetchone()
    assert tuple(admin) == ("", 1)
    new = db.execute("SELECT username, is_admin FROM users WHERE oidc_sub = 'attacker'").fetchone()
    assert new["username"] != "admin" and new["is_admin"] == 0


def test_unverified_email_does_not_link(sso, provider, db):
    provider.who = {"sub": "u-5", "preferred_username": "x", "email": "alice@example.com"}
    web_sso_login(sso, provider)
    assert db.execute("SELECT oidc_sub FROM users WHERE username = 'alice'").fetchone()[0] == ""


def test_link_by_username_is_optional_and_never_for_admins(sso_cfg, provider, db):
    from rdapi.security import create_user

    app = create_app(replace(sso_cfg, oidc_link_by_username=True))
    create_user(db, "dave", USER_PW)
    with TestClient(app) as c:
        provider.who = {"sub": "u-6", "preferred_username": "dave"}
        web_sso_login(c, provider)
        c.cookies.clear()
        provider.who = {"sub": "u-7", "preferred_username": "admin"}
        web_sso_login(c, provider)
    assert db.execute("SELECT oidc_sub FROM users WHERE username = 'dave'").fetchone()[0] == "u-6"
    assert db.execute("SELECT oidc_sub FROM users WHERE username = 'admin'").fetchone()[0] == ""
