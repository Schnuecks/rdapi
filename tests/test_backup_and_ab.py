"""Sicherungen und Adressbuch in der Weboberfläche."""

from __future__ import annotations

import json
import re
from dataclasses import replace

from conftest import USER_PW, app_login, web_login
from fastapi.testclient import TestClient

from rdapi import backup
from rdapi.main import create_app


def backup_names(client) -> list[str]:
    return re.findall(r'href="/backups/(rdapi-[\d-]+\.sqlite3)"', client.get("/backups").text)


def test_backups_page_is_admin_only(client):
    web_login(client, "alice", USER_PW)
    assert client.get("/backups").status_code == 403


def test_create_download_and_restore(client, cfg, db):
    csrf = web_login(client)
    assert client.post("/backups/new", data={"csrf": csrf}).status_code == 200
    names = backup_names(client)
    assert len(names) == 1
    download = client.get(f"/backups/{names[0]}")
    assert download.status_code == 200
    assert download.content.startswith(b"SQLite format 3")

    db.execute("UPDATE users SET display_name = 'Neu' WHERE username = 'alice'")
    resp = client.post(f"/backups/{names[0]}/restore", data={"csrf": csrf})
    assert resp.status_code == 200
    assert db.execute("SELECT display_name FROM users WHERE username = 'alice'").fetchone()[0] == ""
    # Vor dem Zurückspielen wurde der damalige Stand gesichert.
    assert len(backup.list_backups(cfg.backups_path)) == 2


def test_upload_rejects_other_files(client):
    csrf = web_login(client)
    resp = client.post(
        "/backups/upload",
        data={"csrf": csrf},
        files={"file": ("x.sqlite3", b"kein sqlite", "application/octet-stream")},
    )
    assert resp.status_code == 400
    assert backup_names(client) == []


def test_upload_accepts_a_downloaded_backup(client):
    csrf = web_login(client)
    client.post("/backups/new", data={"csrf": csrf})
    data = client.get(f"/backups/{backup_names(client)[0]}").content
    resp = client.post(
        "/backups/upload",
        data={"csrf": csrf},
        files={"file": ("kopie.sqlite3", data, "application/octet-stream")},
    )
    assert resp.status_code == 200
    assert "You can now restore it" in resp.text


def test_backup_names_cannot_leave_the_folder(client):
    web_login(client)
    assert client.get("/backups/..%2Ftest.sqlite3").status_code in (403, 404)
    assert client.get("/backups/rdapi-1.sqlite3").status_code == 403


def test_backups_keep_only_the_newest(tmp_path, cfg):
    folder = tmp_path / "b"
    folder.mkdir()
    for stamp in ("20260101-000000", "20260102-000000", "20260103-000000"):
        (folder / f"rdapi-{stamp}.sqlite3").write_bytes(b"x")
    backup.prune_backups(folder, 2)
    assert [b.name for b in backup.list_backups(folder)] == [
        "rdapi-20260103-000000.sqlite3",
        "rdapi-20260102-000000.sqlite3",
    ]


def test_daily_backup_on_start(cfg):
    app = create_app(replace(cfg, backup_keep=3))
    with TestClient(app):
        pass
    assert len(backup.list_backups(cfg.backups_path)) == 1


def ab_peers(client, headers) -> list[dict]:
    guid = client.post("/api/ab/personal", headers=headers, json={}).json()["guid"]
    return client.post(f"/api/ab/peers?ab={guid}", headers=headers, json={}).json()["data"]


def test_address_book_editing_in_the_web(client):
    headers = app_login(client)
    guid = client.post("/api/ab/personal", headers=headers, json={}).json()["guid"]
    # Eintrag aus der App mit Feldern, die nur die App kennt.
    client.post(
        f"/api/ab/peer/add/{guid}",
        headers=headers,
        json={"id": "100200300", "hash": "geheim", "platform": "Windows", "alias": "Alt"},
    )
    csrf = web_login(client, "alice", USER_PW)

    client.post("/address-book/tags", data={"csrf": csrf, "name": "Büro", "color": "#ff0000"})
    client.post(
        "/address-book/peers",
        data={
            "csrf": csrf,
            "original": "100200300",
            "peer_id": "100200300",
            "alias": "Neu",
            "note": "Drucker",
            "tags": ["Büro", "gibt es nicht"],
        },
    )
    client.post(
        "/address-book/peers",
        data={"csrf": csrf, "original": "", "peer_id": "900 800 700", "alias": "Laptop"},
    )
    peers = {p["id"]: p for p in ab_peers(client, headers)}
    assert peers["100200300"]["alias"] == "Neu"
    assert peers["100200300"]["hash"] == "geheim"  # bleibt erhalten
    assert peers["100200300"]["tags"] == ["Büro"]
    assert peers["900800700"]["alias"] == "Laptop"
    tags = client.post(f"/api/ab/tags/{guid}", headers=headers, json={}).json()
    assert tags == [{"name": "Büro", "color": 0xFFFF0000}]

    # Doppelte ID wird abgelehnt.
    dup = client.post(
        "/address-book/peers",
        data={"csrf": csrf, "original": "900800700", "peer_id": "100200300"},
    )
    assert dup.status_code == 400

    # Tag umbenennen ändert die Einträge mit, Löschen entfernt ihn.
    client.post(
        "/address-book/tags",
        data={"csrf": csrf, "original": "Büro", "name": "Arbeit", "color": "#00ff00"},
    )
    assert {p["id"]: p for p in ab_peers(client, headers)}["100200300"]["tags"] == ["Arbeit"]
    client.post("/address-book/tags/delete", data={"csrf": csrf, "name": "Arbeit"})
    assert {p["id"]: p for p in ab_peers(client, headers)}["100200300"]["tags"] == []

    client.post("/address-book/peers/delete", data={"csrf": csrf, "peer_id": "900800700"})
    assert [p["id"] for p in ab_peers(client, headers)] == ["100200300"]
    page = client.get("/address-book").text
    assert "geheim" not in page
    assert json.dumps("geheim") not in page
