from __future__ import annotations

from dataclasses import replace

import pytest
from conftest import ADMIN_PW, USER_PW, app_login, web_login
from fastapi.testclient import TestClient


def test_pages_require_login(client):
    for path in ("/", "/history", "/address-book", "/account", "/users"):
        resp = client.get(path, follow_redirects=False)
        assert resp.status_code == 303
        assert resp.headers["location"].startswith("/login?next=")


def test_login_wrong_password(client):
    resp = client.post("/login", data={"username": "admin", "password": "falsch"})
    assert resp.status_code == 401
    assert "Wrong username" in resp.text


def test_login_redirect_target_is_local_only(client):
    resp = client.post(
        "/login",
        data={"username": "admin", "password": ADMIN_PW, "next": "//evil.example"},
        follow_redirects=False,
    )
    assert resp.headers["location"] == "/"


def test_admin_pages_render(client):
    client.post("/api/sysinfo", json={"id": "111", "hostname": "WOHNZIMMER", "os": "windows"})
    client.post(
        "/api/audit/conn", json={"id": "111", "conn_id": 1, "action": "new", "ip": "198.51.100.1"}
    )
    web_login(client)
    for path in (
        "/",
        "/devices/111",
        "/history",
        "/history?device=111",
        "/address-book",
        "/account",
        "/users",
        "/logins",
    ):
        resp = client.get(path)
        assert resp.status_code == 200, path
    assert "WOHNZIMMER" in client.get("/").text
    assert "198.51.100.1" in client.get("/history").text


def test_normal_user_cannot_open_admin_pages(client):
    web_login(client, "alice", USER_PW)
    assert client.get("/users").status_code == 403
    assert client.get("/logins").status_code == 403


def test_normal_user_sees_only_own_devices(client):
    client.post("/api/sysinfo", json={"id": "111", "hostname": "MEINER"})
    client.post("/api/sysinfo", json={"id": "222", "hostname": "FREMD"})
    app_login(client, device="111")
    web_login(client, "alice", USER_PW)
    page = client.get("/").text
    assert "MEINER" in page and "FREMD" not in page
    assert client.get("/devices/222").status_code == 403


def test_csrf_required(client):
    web_login(client)
    resp = client.post(
        "/users/new", data={"username": "x", "password": "langes-passwort", "csrf": "falsch"}
    )
    assert resp.status_code == 403


def test_create_user_and_change_password(client):
    csrf = web_login(client)
    resp = client.post(
        "/users/new",
        data={"csrf": csrf, "username": "bob", "password": "kurz"},
    )
    assert resp.status_code == 400
    resp = client.post(
        "/users/new",
        data={"csrf": csrf, "username": "bob", "password": "langes-passwort-1"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    app_login(client, "bob", "langes-passwort-1")

    # Neues Benutzer-Login in der Weboberfläche und Passwort ändern
    client.cookies.clear()
    csrf = web_login(client, "bob", "langes-passwort-1")
    resp = client.post(
        "/account/password",
        data={
            "csrf": csrf,
            "old": "langes-passwort-1",
            "new": "neues-passwort-2",
            "new2": "neues-passwort-2",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 303
    # App-Anmeldung mit altem Passwort geht nicht mehr, mit neuem schon.
    assert (
        client.post(
            "/api/login", json={"username": "bob", "password": "langes-passwort-1"}
        ).status_code
        == 401
    )
    app_login(client, "bob", "neues-passwort-2")


def test_admin_cannot_lock_self(client, db):
    csrf = web_login(client)
    admin_id = db.execute("SELECT id FROM users WHERE username = 'admin'").fetchone()[0]
    resp = client.post(f"/users/{admin_id}", data={"csrf": csrf, "is_admin": "1"})
    assert resp.status_code == 400
    resp = client.post(f"/users/{admin_id}/delete", data={"csrf": csrf})
    assert resp.status_code == 400


def test_disable_user_ends_app_session(client, db):
    headers = app_login(client)
    csrf = web_login(client)
    user_id = db.execute("SELECT id FROM users WHERE username = 'alice'").fetchone()[0]
    resp = client.post(f"/users/{user_id}", data={"csrf": csrf}, follow_redirects=False)
    assert resp.status_code == 303
    assert client.post("/api/currentUser", headers=headers, json={}).status_code == 401


def test_logout(client):
    csrf = web_login(client)
    resp = client.post("/logout", data={"csrf": csrf}, follow_redirects=False)
    assert resp.status_code == 303
    assert client.get("/", follow_redirects=False).status_code == 303


def test_healthz(client):
    assert client.get("/healthz").json() == {"status": "ok"}


def test_language_from_browser_and_cookie(client):
    page = client.get("/login", headers={"Accept-Language": "de-DE,de;q=0.9"}).text
    assert "Benutzername" in page and 'lang="de"' in page
    page = client.get("/login", headers={"Accept-Language": "fr-FR"}).text
    assert "Nom d’utilisateur" in page and 'lang="fr"' in page
    page = client.get("/login", headers={"Accept-Language": "ja-JP"}).text
    assert "Username" in page and 'lang="en"' in page
    client.post("/appearance", data={"lang": "de", "next": "/login"}, follow_redirects=False)
    assert "Benutzername" in client.get("/login").text
    client.post("/appearance", data={"lang": "auto", "next": "/login"}, follow_redirects=False)
    assert "Username" in client.get("/login").text


def test_theme_cookie(client):
    assert "data-theme" not in client.get("/login").text
    resp = client.post(
        "/appearance", data={"theme": "dark", "next": "//evil.example"}, follow_redirects=False
    )
    assert resp.headers["location"] == "/"
    assert 'data-theme="dark"' in client.get("/login").text


def _source_texts() -> set[str]:
    """Alle englischen Texte, die die Oberfläche anzeigen kann."""
    import re
    from pathlib import Path

    from rdapi import backup, i18n, oidc, passkeys, security, web

    root = Path(web.__file__).parent
    keys = set()
    for f in (root / "templates").glob("*.html"):
        keys |= set(re.findall(r"_\('((?:[^'\\]|\\.)*)'", f.read_text(encoding="utf-8")))
    for f in root.glob("*.py"):
        if f.name != "i18n.py":
            keys |= set(re.findall(r'_\("((?:[^"\\]|\\.)*)"', f.read_text(encoding="utf-8")))
    keys |= set(web.CONN_TYPES.values()) | set(web.PRIMARY_AUTH.values())
    keys |= set(web.MESSAGES.values()) | set(i18n.THEME_LABELS.values())
    keys |= set(backup.MESSAGES)
    keys |= set(oidc.MESSAGES)
    keys |= set(passkeys.MESSAGES)
    keys |= set(web.ACTIVITY.values())
    keys.add("unknown")  # Art einer Verbindung, die die App nicht kennt (_connections.html)
    keys |= {
        security.password_problem("x"),
        security.password_problem("x" * 2000),
        security.username_problem(""),
        security.username_problem("x" * 100),
        security.username_problem("a b"),
    }
    return keys


@pytest.mark.parametrize("lang", ["de", "fr", "es", "it", "nl"])
def test_catalog_is_complete(lang):
    """Jede Sprache übersetzt jeden Text, mit denselben Platzhaltern, und nichts Überflüssiges."""
    import json
    import re
    from pathlib import Path

    from rdapi import i18n

    assert lang in i18n.LANGUAGES and lang in i18n.DATE_FORMAT
    path = Path(i18n.__file__).parent / "locales" / f"{lang}.json"
    catalog = json.loads(path.read_text(encoding="utf-8"))
    keys = _source_texts()
    assert sorted(keys - catalog.keys()) == []
    assert sorted(catalog.keys() - keys) == []
    for key, text in catalog.items():
        assert text.strip(), key
        assert set(re.findall(r"\{\w+\}", key)) == set(re.findall(r"\{\w+\}", text)), key


def test_language_menu_offers_all_languages(client):
    page = client.get("/login").text
    for name in ("Deutsch", "English", "Français", "Español", "Italiano", "Nederlands"):
        assert name in page
    resp = client.get("/login", headers={"Accept-Language": "nl-NL,nl;q=0.9"})
    assert 'lang="nl"' in resp.text
    resp = client.get("/login", headers={"Accept-Language": "pt-BR"})
    assert 'lang="en"' in resp.text


def test_session_cookie_secure_follows_scheme(client):
    def login(**headers):
        return client.post(
            "/login",
            data={"username": "admin", "password": ADMIN_PW},
            headers=headers,
            follow_redirects=False,
        )

    # Testkonfiguration erzwingt cookie_secure=False; automatisch nach Schema prüfen
    client.app.state.settings = replace(client.app.state.settings, cookie_secure=None)
    assert "secure" not in login().headers["set-cookie"].lower()
    https = TestClient(client.app, base_url="https://testserver")
    resp = https.post(
        "/login", data={"username": "admin", "password": ADMIN_PW}, follow_redirects=False
    )
    assert "secure" in resp.headers["set-cookie"].lower()


def _fresh_app(cfg):
    from rdapi.main import create_app

    return TestClient(create_app(replace(cfg, bootstrap_admin_user="")))


def test_first_admin_via_setup_page(cfg, caplog):
    from rdapi.db import connect
    from rdapi.security import setup_code

    with caplog.at_level("WARNING", logger="rdapi"), _fresh_app(cfg) as c:
        conn = connect(cfg.db_path)
        code = setup_code(conn)
        conn.close()
        assert code in caplog.text

        # Ohne Konto führt jede Seite zur Einrichtung
        resp = c.get("/", follow_redirects=True)
        assert resp.url.path == "/setup"
        assert "Create admin account" in resp.text

        form = {"username": "chef", "password": "langes-passwort-1", "repeat": "langes-passwort-1"}
        resp = c.post("/setup", data={**form, "code": "AAAA-BBBB-CCCC"})
        assert resp.status_code == 401
        resp = c.post("/setup", data={**form, "code": code, "repeat": "anders-passwort-1"})
        assert resp.status_code == 400
        # Code ohne Bindestriche und klein geschrieben wird akzeptiert
        resp = c.post(
            "/setup", data={**form, "code": code.replace("-", "").lower()}, follow_redirects=False
        )
        assert resp.status_code == 303
        assert "rdapi_session" in resp.headers["set-cookie"]
        assert "chef" in c.get("/account").text

        # Danach ist die Einrichtung zu und der Code verbraucht
        assert c.get("/setup", follow_redirects=False).headers["location"] == "/"
        resp = c.post(
            "/setup", data={**form, "username": "zweiter", "code": code}, follow_redirects=False
        )
        assert resp.status_code == 303
        conn = connect(cfg.db_path)
        users = [r[0] for r in conn.execute("SELECT username FROM users")]
        assert users == ["chef"]
        assert conn.execute("SELECT COUNT(*) FROM settings").fetchone()[0] == 0
        conn.close()
        # Das Konto funktioniert auch in der App
        assert (
            c.post("/api/login", json={"username": "chef", "password": "langes-passwort-1"}).json()[
                "user"
            ]["is_admin"]
            is True
        )


def test_setup_code_is_rate_limited(cfg):
    with _fresh_app(cfg) as c:
        form = {"username": "chef", "password": "langes-passwort-1", "repeat": "langes-passwort-1"}
        for _ in range(5):
            c.post("/setup", data={**form, "code": "falsch"})
        assert c.post("/setup", data={**form, "code": "falsch"}).status_code == 429


def test_cli_setup_code(cfg, monkeypatch, capsys):
    import pytest

    from rdapi import cli

    monkeypatch.setenv("RDAPI_DB_PATH", cfg.db_path)
    monkeypatch.delenv("RDAPI_ADMIN_USER", raising=False)
    with _fresh_app(cfg):
        cli.main(["setup-code"])
        code = capsys.readouterr().out.strip()
        assert len(code) == 14 and code.count("-") == 2
    # Sobald es ein Konto gibt, meldet die CLI das Ende der Einrichtung
    from rdapi.db import connect
    from rdapi.security import create_user

    conn = connect(cfg.db_path)
    create_user(conn, "chef", "langes-passwort-1", is_admin=True)
    conn.close()
    with pytest.raises(SystemExit):
        cli.main(["setup-code"])
