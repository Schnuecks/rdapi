"""Nachgestellte Aufrufe des RustDesk-Clients 1.5.x."""

from __future__ import annotations

import json

from conftest import USER_PW, app_login

# Der Client setzt bei POSTs ohne Body Content-Length: 0 (_setEmptyBody).
EMPTY = {"Content-Type": "application/json", "Content-Length": "0"}


def test_login_returns_token_and_user(client):
    resp = client.post(
        "/api/login",
        json={"username": "alice", "password": USER_PW, "id": "123", "uuid": "u"},
    )
    body = resp.json()
    assert resp.status_code == 200
    assert body["type"] == "access_token"
    assert body["access_token"]
    assert body["user"]["name"] == "alice"
    assert body["user"]["status"] == 1
    assert body["user"]["is_admin"] is False
    assert body["user"]["info"] == {}


def test_login_wrong_password(client):
    resp = client.post("/api/login", json={"username": "alice", "password": "falsch"})
    assert resp.status_code == 401
    assert "error" in resp.json()


def test_login_rate_limited(client):
    for _ in range(5):
        client.post("/api/login", json={"username": "alice", "password": "falsch"})
    resp = client.post("/api/login", json={"username": "alice", "password": USER_PW})
    assert resp.status_code == 429


def test_login_other_types_rejected(client):
    resp = client.post("/api/login", json={"type": "email_code", "username": "alice"})
    assert resp.status_code == 400


def test_login_options_empty(client):
    resp = client.get("/api/login-options")
    assert resp.status_code == 200
    assert resp.json() == []


def test_current_user_and_logout(client):
    headers = app_login(client)
    resp = client.post("/api/currentUser", headers=headers, json={"id": "1", "uuid": "u"})
    assert resp.status_code == 200
    assert resp.json()["name"] == "alice"

    resp = client.post("/api/logout", headers=headers, json={"id": "1", "uuid": "u"})
    assert resp.status_code == 200
    assert resp.content == b""

    resp = client.post("/api/currentUser", headers=headers, json={})
    assert resp.status_code == 401


def test_disabled_user_token_invalid(client, db):
    headers = app_login(client)
    db.execute("UPDATE users SET enabled = 0 WHERE username = 'alice'")
    assert client.post("/api/currentUser", headers=headers, json={}).status_code == 401
    resp = client.post("/api/login", json={"username": "alice", "password": USER_PW})
    assert resp.status_code == 401


def test_heartbeat_sysinfo_flow(client, db):
    # Unbekanntes Gerät: Server fordert Sysinfo an.
    resp = client.post("/api/heartbeat", json={"id": "987654321", "uuid": "u", "ver": 1005000})
    assert resp.json() == {"sysinfo": True}

    sysinfo = {
        "cpu": "Intel, 3.2GHz, 8/4 cores",
        "memory": "16GB",
        "os": "windows / Windows 11 Pro",
        "hostname": "WOHNZIMMER",
        "username": "oma",
        "version": "1.5.0",
        "id": "987654321",
        "uuid": "u",
    }
    resp = client.post("/api/sysinfo", content=json.dumps(sysinfo))
    assert resp.text == "SYSINFO_UPDATED"

    resp = client.post("/api/heartbeat", json={"id": "987654321", "uuid": "u", "modified_at": 0})
    assert resp.json() == {}
    row = db.execute("SELECT * FROM devices WHERE id = '987654321'").fetchone()
    assert row["hostname"] == "WOHNZIMMER"
    assert row["version"] == "1.5.0"
    assert row["last_seen_at"]

    assert client.post("/api/sysinfo_ver", content="").text == ""


def test_login_assigns_device(client, db):
    client.post("/api/sysinfo", json={"id": "111222333", "hostname": "PC"})
    app_login(client, device="111222333")
    owner = db.execute(
        "SELECT u.username FROM devices d JOIN users u ON u.id = d.user_id WHERE d.id = '111222333'"
    ).fetchone()[0]
    assert owner == "alice"


def test_audit_conn_lifecycle_and_dedup(client, db):
    client.post("/api/sysinfo", json={"id": "111222333", "uuid": "u", "hostname": "PC"})
    base = {"id": "111222333", "uuid": "u", "conn_id": 7, "session_id": 0}
    new = {**base, "ip": "203.0.113.5", "action": "new", "nonce": "n1"}
    assert client.post("/api/audit/conn", json=new).content == b""
    # Wiederholung mit gleicher Nonce darf keinen zweiten Eintrag erzeugen.
    assert client.post("/api/audit/conn", json=new).content == b""
    auth = {
        **base,
        "session_id": 123456789012345678,
        "peer": ["555666777", "Laptop"],
        "type": 0,
        "primary_auth": 3,
        "nonce": "n2",
    }
    assert client.post("/api/audit/conn", json=auth).status_code == 200
    close = {**base, "action": "close", "nonce": "n3"}
    assert client.post("/api/audit/conn", json=close).status_code == 200

    rows = db.execute("SELECT * FROM connections").fetchall()
    assert len(rows) == 1
    row = rows[0]
    assert row["ip"] == "203.0.113.5"
    assert row["peer_id"] == "555666777"
    assert row["peer_name"] == "Laptop"
    assert row["conn_type"] == 0
    assert row["primary_auth"] == 3
    assert row["session_id"] == "123456789012345678"
    assert row["authed_at"] and row["ended_at"]


def test_audit_file_and_alarm(client, db):
    client.post("/api/sysinfo", json={"id": "1", "uuid": "u", "hostname": "PC"})
    file_audit = {"id": "1", "uuid": "u", "nonce": "f"}
    assert client.post("/api/audit/file", json=file_audit).content == b""
    alarm = {"id": "1", "uuid": "u", "typ": 1}
    assert client.post("/api/audit/alarm", json=alarm).content == b""
    assert db.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0] == 2
    assert client.post("/api/audit/foo", json={}).status_code == 404


def test_users_and_peers_for_normal_user(client):
    headers = app_login(client, device="111222333")
    client.post(
        "/api/sysinfo",
        json={"id": "111222333", "uuid": "dXVpZA==", "hostname": "PC", "os": "windows / 11"},
    )
    query = {"current": 1, "pageSize": 100, "accessible": "", "status": 1}
    users = client.get("/api/users", params=query, headers=headers).json()
    assert users["total"] == 1
    assert users["data"][0]["name"] == "alice"

    peers = client.get("/api/peers", params=query, headers=headers).json()
    assert peers["total"] == 1
    peer = peers["data"][0]
    assert peer["id"] == "111222333"
    assert peer["user_name"] == "alice"
    assert peer["info"]["device_name"] == "PC"

    groups = client.get("/api/device-group/accessible", params=query, headers=headers).json()
    assert groups == {"total": 0, "data": []}


def test_admin_sees_all_users(client):
    app_login(client, device="1")
    headers = app_login(client, username="admin", password="admin-passwort-1", device="2")
    users = client.get("/api/users", headers=headers).json()
    assert {u["name"] for u in users["data"]} == {"admin", "alice"}
    peers = client.get("/api/peers", headers=headers).json()
    assert {p["id"] for p in peers["data"]} == {"1", "2"}


def test_group_endpoints_require_login(client):
    assert client.get("/api/users").status_code == 401
    assert client.post("/api/ab/personal", headers=EMPTY).status_code == 401


def _personal_guid(client, headers):
    resp = client.post("/api/ab/personal", headers={**headers, **EMPTY})
    assert resp.status_code == 200
    return resp.json()["guid"]


def test_address_book_flow(client):
    headers = app_login(client)
    h = {**headers, "Content-Type": "application/json"}

    assert client.post("/api/ab/settings", headers={**headers, **EMPTY}).json() == {
        "max_peer_one_ab": 0
    }
    guid = _personal_guid(client, headers)
    assert guid == _personal_guid(client, headers)
    shared = client.post(
        "/api/ab/shared/profiles?current=1&pageSize=100", headers={**headers, **EMPTY}
    ).json()
    assert shared == {"total": 0, "data": []}

    # Tag anlegen, Eintrag hinzufügen
    resp = client.post(
        f"/api/ab/tag/add/{guid}", headers=h, json={"name": "Familie", "color": 4283215696}
    )
    assert resp.status_code == 200 and resp.content == b""
    peer = {
        "id": "555666777",
        "alias": "Oma",
        "tags": ["Familie"],
        "hash": "abc",
        "username": "oma",
        "hostname": "WOHNZIMMER",
        "platform": "Windows",
        "note": "",
    }
    resp = client.post(f"/api/ab/peer/add/{guid}", headers=h, content=json.dumps(peer))
    assert resp.status_code == 200 and resp.content == b""

    # Alias, Notiz und Tags ändern (je ein PUT mit Teilfeldern)
    for change in ({"alias": "Oma Erna"}, {"note": "Wohnzimmer-PC"}, {"tags": ["Familie", "Neu"]}):
        resp = client.put(
            f"/api/ab/peer/update/{guid}", headers=h, json={"id": "555666777", **change}
        )
        assert resp.status_code == 200 and resp.content == b""

    peers = client.post(
        f"/api/ab/peers?current=1&pageSize=100&ab={guid}", headers={**headers, **EMPTY}
    ).json()
    assert peers["total"] == 1
    stored = peers["data"][0]
    assert stored["alias"] == "Oma Erna"
    assert stored["note"] == "Wohnzimmer-PC"
    assert stored["hash"] == "abc"
    assert stored["tags"] == ["Familie", "Neu"]

    # Tag umbenennen, Farbe ändern, löschen
    resp = client.put(
        f"/api/ab/tag/rename/{guid}", headers=h, json={"old": "Familie", "new": "Fam"}
    )
    assert resp.content == b""
    resp = client.put(f"/api/ab/tag/update/{guid}", headers=h, json={"name": "Fam", "color": 1})
    assert resp.content == b""
    tags = client.post(f"/api/ab/tags/{guid}", headers={**headers, **EMPTY}).json()
    assert tags == [{"name": "Fam", "color": 1}]
    stored = client.post(f"/api/ab/peers?ab={guid}", headers={**headers, **EMPTY}).json()["data"][0]
    assert stored["tags"] == ["Fam", "Neu"]

    resp = client.request("DELETE", f"/api/ab/tag/{guid}", headers=h, content=json.dumps(["Fam"]))
    assert resp.content == b""
    stored = client.post(f"/api/ab/peers?ab={guid}", headers={**headers, **EMPTY}).json()["data"][0]
    assert stored["tags"] == ["Neu"]
    assert client.post(f"/api/ab/tags/{guid}", headers={**headers, **EMPTY}).json() == []

    # Eintrag löschen
    resp = client.request(
        "DELETE", f"/api/ab/peer/{guid}", headers=h, content=json.dumps(["555666777"])
    )
    assert resp.content == b""
    peers = client.post(f"/api/ab/peers?ab={guid}", headers={**headers, **EMPTY}).json()
    assert peers == {"total": 0, "data": []}


def test_address_book_update_unknown_peer(client):
    headers = app_login(client)
    guid = _personal_guid(client, headers)
    resp = client.put(
        f"/api/ab/peer/update/{guid}", headers=headers, json={"id": "x", "alias": "y"}
    )
    assert resp.status_code == 400
    assert resp.json()["error"]


def test_address_book_of_other_user_forbidden(client):
    admin = app_login(client, username="admin", password="admin-passwort-1")
    admin_guid = _personal_guid(client, admin)
    headers = app_login(client)
    resp = client.post(f"/api/ab/peers?ab={admin_guid}", headers={**headers, **EMPTY})
    assert resp.status_code == 403
    resp = client.post(f"/api/ab/peer/add/{admin_guid}", headers=headers, json={"id": "1"})
    assert resp.status_code == 403


def test_address_book_pagination(client):
    headers = app_login(client)
    guid = _personal_guid(client, headers)
    for i in range(5):
        client.post(f"/api/ab/peer/add/{guid}", headers=headers, json={"id": str(i)})
    page = client.post(
        f"/api/ab/peers?current=2&pageSize=2&ab={guid}", headers={**headers, **EMPTY}
    ).json()
    assert page["total"] == 5
    assert [p["id"] for p in page["data"]] == ["2", "3"]


def test_legacy_address_book_roundtrip(client):
    headers = app_login(client)
    book = {
        "tags": ["A"],
        "peers": [{"id": "1", "alias": "x", "tags": ["A"], "hash": "h"}],
        "tag_colors": json.dumps({"A": 123}),
    }
    resp = client.post("/api/ab", headers=headers, json={"data": json.dumps(book)})
    assert resp.status_code == 200 and resp.content == b""
    data = json.loads(client.get("/api/ab", headers=headers).json()["data"])
    assert data["tags"] == ["A"]
    assert data["peers"][0]["alias"] == "x"
    assert json.loads(data["tag_colors"]) == {"A": 123}
    # Das neue Format sieht dieselben Daten.
    guid = _personal_guid(client, headers)
    peers = client.post(f"/api/ab/peers?ab={guid}", headers={**headers, **EMPTY}).json()
    assert peers["data"][0]["id"] == "1"


def test_invalid_json(client):
    headers = app_login(client)
    resp = client.post("/api/ab", headers=headers, content=b"{kaputt")
    assert resp.status_code == 400
    assert resp.json()["error"] == "Invalid JSON."
