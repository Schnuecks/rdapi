from __future__ import annotations

import csv
import io
import json

from conftest import USER_PW, app_login, web_login
from test_sharing import _share, _shared_book, _user_id

from rdapi.db import now


def _alarm(client, typ, info: dict, nonce: str, device: str = "111222333"):
    body = {"id": device, "uuid": "dXVpZA==", "typ": typ, "info": json.dumps(info), "nonce": nonce}
    assert client.post("/api/audit/alarm", json=body).content == b""


def test_alarms_in_history(client, db):
    app_login(client, device="111222333")
    client.post("/api/sysinfo", json={"id": "111222333", "uuid": "dXVpZA==", "hostname": "PC"})
    _alarm(client, 2, {"ip": "198.51.100.9", "id": "444555666", "name": "Fremd"}, "a")
    _alarm(client, 9, {"ip": "198.51.100.10", "message": "file transfer denied"}, "b")
    _alarm(client, 42, {"ip": "198.51.100.11"}, "c")
    web_login(client, "alice", USER_PW)
    page = client.get("/history/alarms").text
    assert "More than 6 wrong passwords within a minute" in page
    assert "444555666" in page and "Fremd" in page and "198.51.100.9" in page
    assert "Connection went beyond what it was allowed to do" in page
    assert "file transfer denied" in page
    assert "Other alarm (42)" in page
    assert 'href="/history/alarms"' in client.get("/history").text
    # Filter auf ein Gerät und fremde Geräte.
    assert client.get("/history/alarms?device=999").text.count("<tr>") == 0
    db.execute(
        "INSERT INTO audit_events (kind, device_id, payload, created_at)"
        " VALUES ('alarm', 'x', '{\"typ\": 1}', ?)",
        (now(),),
    )
    assert client.get("/history/alarms").text.count("<tr>") == 4  # Kopf + 3 eigene
    web_login(client)
    assert client.get("/history/alarms").text.count("<tr>") == 5  # Admin sieht alle


def test_alarm_page_survives_odd_payloads(client, db):
    web_login(client)
    for payload in ("not json", "[]", '{"typ": true, "info": "[1]"}', '{"info": "{"}'):
        db.execute(
            "INSERT INTO audit_events (kind, device_id, payload, created_at)"
            " VALUES ('alarm', 'x', ?, ?)",
            (payload, now()),
        )
    page = client.get("/history/alarms")
    assert page.status_code == 200
    assert page.text.count("Other alarm (?)") == 4


def _personal(client, headers) -> str:
    return client.post("/api/ab/personal", headers=headers, json={}).json()["guid"]


def _peers(client, headers) -> dict[str, dict]:
    guid = _personal(client, headers)
    data = client.post(f"/api/ab/peers?ab={guid}", headers=headers, json={}).json()["data"]
    return {p["id"]: p for p in data}


def _import(client, csrf, content: str, name="ab.json", book=""):
    return client.post(
        "/address-book/import",
        data={"csrf": csrf, "book": book},
        files={"file": (name, content.encode(), "application/octet-stream")},
    )


def test_export_json_and_csv_without_saved_passwords(client):
    headers = app_login(client)
    guid = _personal(client, headers)
    client.post(
        f"/api/ab/tag/add/{guid}", headers=headers, json={"name": "Büro", "color": 0xFFFF0000}
    )
    client.post(
        f"/api/ab/peer/add/{guid}",
        headers=headers,
        json={
            "id": "100200300",
            "hash": "geheim",
            "password": "auch-geheim",
            "alias": "=HYPERLINK(1)",
            "tags": ["Büro"],
            "platform": "Windows",
        },
    )
    web_login(client, "alice", USER_PW)
    resp = client.get("/address-book/export?format=json")
    assert resp.status_code == 200
    assert "attachment" in resp.headers["content-disposition"]
    assert "address-book-alice.json" in resp.headers["content-disposition"]
    assert "geheim" not in resp.text
    data = resp.json()
    assert data["format"] == "rdapi-address-book"
    assert data["tags"] == [{"name": "Büro", "color": "#ff0000"}]
    assert data["peers"] == [
        {"id": "100200300", "alias": "=HYPERLINK(1)", "platform": "Windows", "tags": ["Büro"]}
    ]

    resp = client.get("/address-book/export?format=csv")
    assert resp.headers["content-type"].startswith("text/csv")
    assert "geheim" not in resp.text
    assert resp.text.startswith("\ufeff")
    rows = list(csv.DictReader(io.StringIO(resp.text.lstrip("\ufeff"))))
    assert rows[0]["id"] == "100200300"
    assert rows[0]["alias"] == "'=HYPERLINK(1)"  # keine Formel im Tabellenprogramm
    assert rows[0]["tags"] == "Büro"
    web_login(client)
    assert "Exported an address book" in client.get("/activity").text


def test_import_merges_and_keeps_saved_passwords(client, db):
    headers = app_login(client)
    guid = _personal(client, headers)
    client.post(
        f"/api/ab/peer/add/{guid}",
        headers=headers,
        json={"id": "100200300", "hash": "geheim", "alias": "Alt", "tags": ["Haus"]},
    )
    client.post(f"/api/ab/tag/add/{guid}", headers=headers, json={"name": "Haus", "color": 1})
    csrf = web_login(client, "alice", USER_PW)
    export = {
        "format": "rdapi-address-book",
        "version": 1,
        "tags": [{"name": "Büro", "color": "#00ff00"}],
        "peers": [
            {"id": "100200300", "alias": "Neu", "tags": ["Büro"], "hash": "fremd"},
            {"id": "900 800 700", "alias": "Laptop", "note": "x" * 900, "password": "p"},
            {"alias": "ohne ID"},
        ],
    }
    resp = _import(client, csrf, json.dumps(export))
    assert resp.status_code == 200
    assert "Import finished: 1 new, 1 updated, 1 skipped." in resp.text
    peers = _peers(client, headers)
    assert peers["100200300"]["alias"] == "Neu"
    assert peers["100200300"]["hash"] == "geheim"  # nicht aus der Datei überschrieben
    assert peers["100200300"]["tags"] == ["Haus", "Büro"]
    assert peers["900800700"]["alias"] == "Laptop"
    assert len(peers["900800700"]["note"]) == 500
    assert "password" not in peers["900800700"]
    tags = client.post(f"/api/ab/tags/{guid}", headers=headers, json={}).json()
    assert {"name": "Büro", "color": 0xFF00FF00} in tags
    assert db.execute("SELECT detail FROM activity WHERE action = 'ab_imported'").fetchone()[0] == (
        "1 new, 1 updated, 1 skipped"
    )

    # Eine exportierte Datei lässt sich unverändert wieder einlesen.
    again = client.get("/address-book/export?format=json").text
    assert "0 new, 2 updated, 0 skipped" in _import(client, csrf, again).text


def test_import_csv(client):
    headers = app_login(client)
    csrf = web_login(client, "alice", USER_PW)
    table = "\ufeffName;x\n"  # ohne Spalte id
    resp = _import(client, csrf, table, "ab.csv")
    assert resp.status_code == 400 and "needs a column named id" in resp.text
    table = "id,Alias,tags,unbekannt\n111,Eins,A;B,x\n,leer,,\n222,Zwei,,\n"
    resp = _import(client, csrf, table, "ab.csv")
    assert "2 new, 0 updated, 1 skipped" in resp.text
    peers = _peers(client, headers)
    assert peers["111"]["alias"] == "Eins" and peers["111"]["tags"] == ["A", "B"]
    assert "unbekannt" not in peers["111"]
    assert peers["222"]["tags"] == []
    # Mit Semikolon getrennt, wie ein deutsches Tabellenprogramm speichert.
    resp = _import(client, csrf, 'id;alias;tags\n333;Drei;"A;C"\n', "ab.csv")
    assert "1 new, 0 updated, 0 skipped" in resp.text
    assert _peers(client, headers)["333"]["tags"] == ["A", "C"]


def test_import_rejects_bad_files(client):
    csrf = web_login(client, "alice", USER_PW)
    for content in ('{"peers": 1}', "{kaputt", '{"format": "x"}'):
        resp = _import(client, csrf, content)
        assert resp.status_code == 400 and "not a valid address book export" in resp.text
    resp = client.post(
        "/address-book/import",
        data={"csrf": csrf},
        files={"file": ("ab.csv", b"\xff\xfe\x00", "text/csv")},
    )
    assert resp.status_code == 400
    many = {"peers": [{"id": str(i)} for i in range(5001)]}
    resp = _import(client, csrf, json.dumps(many))
    assert resp.status_code == 400 and "too many entries" in resp.text
    resp = client.post(
        "/address-book/import",
        data={"csrf": "falsch"},
        files={"file": ("ab.json", b'{"peers": []}', "application/json")},
    )
    assert resp.status_code == 403


def test_import_needs_write_access_to_a_shared_book(client, db):
    admin_csrf = web_login(client)
    client.get("/address-book")  # legt das persönliche Adressbuch des Admins an
    guid = _shared_book(client, admin_csrf)
    client.post(
        "/address-book/peers",
        data={"csrf": admin_csrf, "book": guid, "peer_id": "777", "alias": "Dad"},
    )
    _share(client, admin_csrf, guid, f"u:{_user_id(db, 'alice')}", 1)
    content = json.dumps({"peers": [{"id": "888"}]})
    assert "1 new" in _import(client, admin_csrf, content, book=guid).text

    csrf = web_login(client, "alice", USER_PW)
    page = client.get(f"/address-book?book={guid}").text
    assert "Export as JSON" in page and "File to import" not in page
    export = client.get(f"/address-book/export?book={guid}&format=json")
    assert export.status_code == 200
    assert "address-book-Family.json" in export.headers["content-disposition"]
    assert [p["id"] for p in export.json()["peers"]] == ["777", "888"]
    assert _import(client, csrf, content, book=guid).status_code == 403
    # Fremde Adressbücher lassen sich nicht exportieren.
    other = db.execute(
        "SELECT guid FROM address_books WHERE user_id = ?", (_user_id(db, "admin"),)
    ).fetchone()
    assert other is not None
    assert client.get(f"/address-book/export?book={other[0]}").status_code == 403
