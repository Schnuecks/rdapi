"""Gruppen, geteilte Adressbücher, Dateiübertragungen im Verlauf und Seiten der Anmeldungen."""

from __future__ import annotations

import json
import re
import sqlite3

from conftest import USER_PW, app_login, web_login

from rdapi.db import MIGRATIONS, connect, init_db, now
from rdapi.security import create_user, log_login


def _user_id(db, name: str) -> int:
    return db.execute("SELECT id FROM users WHERE username = ?", (name,)).fetchone()[0]


def _shared_book(client, csrf: str, name: str = "Family") -> str:
    resp = client.post(
        "/address-book/shared/new",
        data={"csrf": csrf, "name": name, "note": "computers of the parents"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    return re.search(r"book=([0-9a-f-]+)", resp.headers["location"]).group(1)


def _share(client, csrf: str, guid: str, who: str, rule: int) -> None:
    resp = client.post(
        f"/address-book/shared/{guid}/rules",
        data={"csrf": csrf, "who": who, "rule": rule},
        follow_redirects=False,
    )
    assert resp.status_code == 303, resp.text


def test_migration_keeps_personal_address_books(tmp_path):
    path = str(tmp_path / "old.sqlite3")
    conn = sqlite3.connect(path)
    for index, script in enumerate(MIGRATIONS[:6], start=1):
        conn.executescript(f"BEGIN;\n{script}\nPRAGMA user_version = {index};\nCOMMIT;")
    conn.execute(
        "INSERT INTO users (id, username, password_hash, created_at) VALUES (1, 'alice', 'x', 0)"
    )
    conn.execute("INSERT INTO address_books (guid, user_id, created_at) VALUES ('g1', 1, 0)")
    conn.execute(
        "INSERT INTO ab_peers (ab_guid, peer_id, data, position, updated_at)"
        " VALUES ('g1', '123', '{\"id\": \"123\"}', 1, 0)"
    )
    conn.execute("INSERT INTO ab_tags (ab_guid, name, color, position) VALUES ('g1', 'home', 1, 1)")
    conn.commit()
    conn.close()

    init_db(path)
    db = connect(path)
    assert db.execute("PRAGMA user_version").fetchone()[0] == len(MIGRATIONS)
    assert [tuple(r) for r in db.execute("SELECT user_id, name FROM address_books")] == [(1, "")]
    assert db.execute("SELECT COUNT(*) FROM ab_peers").fetchone()[0] == 1
    assert db.execute("SELECT COUNT(*) FROM ab_tags").fetchone()[0] == 1
    # Fremdschlüssel greifen wieder: Benutzer löschen räumt sein Adressbuch mit ab.
    db.execute("DELETE FROM users WHERE id = 1")
    assert db.execute("SELECT COUNT(*) FROM ab_peers").fetchone()[0] == 0
    db.close()


def test_shared_address_book_permissions_in_the_app(client, db):
    csrf = web_login(client)
    guid = _shared_book(client, csrf)
    headers = app_login(client)

    # Noch nicht geteilt: alice sieht es nicht und darf nicht hinein.
    assert client.post("/api/ab/shared/profiles", headers=headers).json() == {
        "total": 0,
        "data": [],
    }
    assert client.post(f"/api/ab/peers?ab={guid}", headers=headers).status_code == 403

    _share(client, csrf, guid, f"u:{_user_id(db, 'alice')}", 1)
    profiles = client.post("/api/ab/shared/profiles", headers=headers).json()
    assert profiles["total"] == 1
    profile = profiles["data"][0]
    assert profile == {
        "guid": guid,
        "name": "Family",
        "owner": "admin",
        "note": "computers of the parents",
        "rule": 1,
    }
    assert client.post(f"/api/ab/peers?ab={guid}", headers=headers).json()["total"] == 0
    assert client.post(f"/api/ab/tags/{guid}", headers=headers).json() == []
    add = client.post(f"/api/ab/peer/add/{guid}", json={"id": "555"}, headers=headers)
    assert add.status_code == 403

    # Lesen und ändern: Eintrag anlegen geht, mit leerer Antwort wie bei der App üblich.
    _share(client, csrf, guid, f"u:{_user_id(db, 'alice')}", 2)
    add = client.post(
        f"/api/ab/peer/add/{guid}", json={"id": "555", "alias": "Mum"}, headers=headers
    )
    assert add.status_code == 200 and add.content == b""
    assert (
        client.post(f"/api/ab/tag/add/{guid}", json={"name": "parents"}, headers=headers).content
        == b""
    )
    peers = client.post(f"/api/ab/peers?ab={guid}", headers=headers).json()
    assert peers["data"][0]["alias"] == "Mum"

    # Das persönliche Adressbuch bleibt getrennt.
    personal = client.post("/api/ab/personal", headers=headers).json()["guid"]
    assert personal != guid
    assert client.post(f"/api/ab/peers?ab={personal}", headers=headers).json()["total"] == 0


def test_address_book_shared_with_a_group(client, db):
    create_user(db, "bob", USER_PW)
    csrf = web_login(client)
    guid = _shared_book(client, csrf, "Office")
    resp = client.post("/groups/new", data={"csrf": csrf, "name": "Family"}, follow_redirects=False)
    group_id = int(resp.headers["location"].split("/")[-1].split("?")[0])
    client.post(
        f"/groups/{group_id}",
        data={"csrf": csrf, "name": "Family", "members": [_user_id(db, "alice")]},
    )
    _share(client, csrf, guid, f"g:{group_id}", 3)

    alice = app_login(client)
    assert client.post("/api/ab/shared/profiles", headers=alice).json()["data"][0]["rule"] == 3
    bob = app_login(client, username="bob", device="999888777")
    assert client.post("/api/ab/shared/profiles", headers=bob).json()["total"] == 0
    assert client.post(f"/api/ab/peers?ab={guid}", headers=bob).status_code == 403


def test_group_members_see_each_others_devices(client, db):
    create_user(db, "bob", USER_PW)
    create_user(db, "carol", USER_PW)
    alice = app_login(client, device="111")
    client.post("/api/sysinfo", json={"id": "111", "uuid": "dXVpZA==", "hostname": "PC-A"})
    bob = app_login(client, username="bob", device="222")
    client.post("/api/sysinfo", json={"id": "222", "uuid": "dXVpZA==", "hostname": "PC-B"})
    app_login(client, username="carol", device="333")
    client.post("/api/sysinfo", json={"id": "333", "uuid": "dXVpZA==", "hostname": "PC-C"})

    def seen(headers):
        peers = client.get("/api/peers", params={"accessible": "", "status": 1}, headers=headers)
        users = client.get("/api/users", params={"accessible": "", "status": 1}, headers=headers)
        return (
            sorted(p["id"] for p in peers.json()["data"]),
            sorted(u["name"] for u in users.json()["data"]),
        )

    assert seen(alice) == (["111"], ["alice"])
    csrf = web_login(client)
    resp = client.post("/groups/new", data={"csrf": csrf, "name": "Family"}, follow_redirects=False)
    group_id = int(resp.headers["location"].split("/")[-1].split("?")[0])
    members = [_user_id(db, "alice"), _user_id(db, "bob")]
    client.post(f"/groups/{group_id}", data={"csrf": csrf, "name": "Family", "members": members})

    assert seen(alice) == (["111", "222"], ["alice", "bob"])
    assert seen(bob) == (["111", "222"], ["alice", "bob"])
    page = client.get("/activity").text
    assert "Created a group" in page and "+alice" in page

    client.post(f"/groups/{group_id}/delete", data={"csrf": csrf})
    assert seen(alice) == (["111"], ["alice"])


def test_only_admins_manage_groups_and_shared_books(client):
    csrf = web_login(client, "alice", USER_PW)
    assert client.post("/groups/new", data={"csrf": csrf, "name": "x"}).status_code == 403
    resp = client.post("/address-book/shared/new", data={"csrf": csrf, "name": "x"})
    assert resp.status_code == 403
    page = client.get("/address-book").text
    assert "New shared address book" not in page


def test_web_shows_shared_book_read_only(client, db):
    admin_csrf = web_login(client)
    guid = _shared_book(client, admin_csrf)
    client.post(
        "/address-book/peers",
        data={"csrf": admin_csrf, "book": guid, "peer_id": "777", "alias": "Dad"},
    )
    _share(client, admin_csrf, guid, f"u:{_user_id(db, 'alice')}", 1)
    page = client.get(f"/address-book?book={guid}").text
    assert "Shared with" in page and "alice" in page

    csrf = web_login(client, "alice", USER_PW)
    page = client.get(f"/address-book?book={guid}").text
    assert "Dad" in page and "Read only" in page
    assert "Add entry" not in page and "Shared with" not in page
    resp = client.post(
        "/address-book/peers", data={"csrf": csrf, "book": guid, "peer_id": "1", "alias": "x"}
    )
    assert resp.status_code == 403
    # Die Auswahl oben führt zum eigenen und zum geteilten Adressbuch.
    tabs = client.get("/address-book").text
    assert f"/address-book?book={guid}" in tabs


def test_file_transfers_in_history(client, db):
    headers = app_login(client, device="111222333")
    client.post("/api/sysinfo", json={"id": "111222333", "uuid": "dXVpZA==", "hostname": "PC"})
    info = {"ip": "192.0.2.7", "name": "Laptop", "num": 7, "files": [["report.pdf", 1000]]}
    for kind, nonce in ((0, "a"), (1, "b")):
        audit = {
            "id": "111222333",
            "uuid": "dXVpZA==",
            "peer_id": "444555666",
            "type": kind,
            "path": "C:/Users/alice",
            "is_file": False,
            "info": json.dumps(info),
            "nonce": nonce,
        }
        assert client.post("/api/audit/file", json=audit).content == b""
    assert headers
    web_login(client, "alice", USER_PW)
    page = client.get("/history/files").text
    assert "Copied from this device" in page and "Copied to this device" in page
    assert "report.pdf" in page and "and 6 more" in page and "444555666" in page
    assert "Laptop" in page
    # Fremde Geräte sieht ein normaler Benutzer nicht.
    db.execute(
        "INSERT INTO audit_events (kind, device_id, payload, created_at)"
        " VALUES ('file', 'x', '{}', ?)",
        (now(),),
    )
    assert client.get("/history/files").text.count("<tr>") == 3  # Kopf + 2 eigene


def test_logins_are_split_into_pages_of_20(client, db):
    for i in range(25):
        log_login(db, f"user{i:02d}", None, "web", "192.0.2.1", False, "")
    web_login(client)  # schreibt eine erfolgreiche Anmeldung dazu: 26 Einträge
    first = client.get("/logins").text
    assert first.count("<tr>") == 21  # Kopf + 20
    assert "Page 1 of 2 (26 entries)" in first
    second = client.get("/logins?page=2").text
    assert second.count("<tr>") == 7
    assert "user00" in second and "user00" not in first
    # Seiten außerhalb des Bereichs zeigen die letzte bzw. erste Seite.
    assert "Page 2 of 2" in client.get("/logins?page=99").text
