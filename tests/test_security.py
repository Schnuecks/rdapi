"""Geräte-Meldungen, Geräte-Besitz, Sperren, Aufräumen und Sicherheits-Header."""

from __future__ import annotations

from dataclasses import replace

from conftest import ADMIN_PW, app_login
from fastapi.testclient import TestClient

from rdapi.db import now, prune
from rdapi.main import create_app
from rdapi.security import LoginLimiter, known_login_ip, log_login


def test_sysinfo_with_other_uuid_does_not_overwrite(client, db):
    client.post("/api/sysinfo", json={"id": "42", "uuid": "echt", "hostname": "Büro-PC"})
    resp = client.post("/api/sysinfo", json={"id": "42", "uuid": "falsch", "hostname": "Fake"})
    assert resp.text == "INVALID"
    assert db.execute("SELECT hostname FROM devices WHERE id = '42'").fetchone()[0] == "Büro-PC"


def test_heartbeat_with_other_uuid_is_ignored(client, db):
    client.post("/api/sysinfo", json={"id": "42", "uuid": "echt", "hostname": "PC"})
    db.execute("UPDATE devices SET last_seen_at = 1, last_ip = 'alt' WHERE id = '42'")
    assert client.post("/api/heartbeat", json={"id": "42", "uuid": "falsch"}).json() == {}
    row = db.execute("SELECT last_seen_at, last_ip FROM devices WHERE id = '42'").fetchone()
    assert tuple(row) == (1, "alt")
    client.post("/api/heartbeat", json={"id": "42", "uuid": "echt"})
    assert db.execute("SELECT last_seen_at FROM devices WHERE id = '42'").fetchone()[0] > 1


def test_audit_from_unknown_or_foreign_device_is_ignored(client, db):
    entry = {"id": "77", "uuid": "u", "conn_id": 1, "action": "new", "nonce": "a"}
    assert client.post("/api/audit/conn", json=entry).content == b""
    client.post("/api/sysinfo", json={"id": "77", "uuid": "u", "hostname": "PC"})
    foreign = {**entry, "uuid": "anders", "nonce": "b"}
    assert client.post("/api/audit/conn", json=foreign).content == b""
    assert db.execute("SELECT COUNT(*) FROM connections").fetchone()[0] == 0
    client.post("/api/audit/conn", json={**entry, "nonce": "c"})
    assert db.execute("SELECT COUNT(*) FROM connections").fetchone()[0] == 1


def test_new_devices_per_address_are_limited(cfg):
    app = create_app(replace(cfg, new_devices_per_hour=3))
    with TestClient(app) as c:
        codes = [
            c.post("/api/sysinfo", json={"id": str(i), "uuid": "u"}).status_code for i in range(5)
        ]
        assert codes == [200, 200, 200, 429, 429]
        # Bekannte Geräte melden sich weiter.
        assert c.post("/api/sysinfo", json={"id": "0", "uuid": "u"}).status_code == 200


def test_login_cannot_take_over_foreign_device(client, db):
    app_login(client, username="admin", password=ADMIN_PW, device="555")
    # alice schickt die ID des Admin-Geräts, aber mit anderer Kennung.
    resp = client.post(
        "/api/login",
        json={"username": "alice", "password": "nutzer-passwort-1", "id": "555", "uuid": "x"},
    )
    assert resp.status_code == 200
    owner = db.execute(
        "SELECT u.username FROM devices d JOIN users u ON u.id = d.user_id WHERE d.id = '555'"
    ).fetchone()[0]
    assert owner == "admin"


def test_login_takes_over_own_device_with_matching_uuid(client, db):
    app_login(client, username="admin", password=ADMIN_PW, device="555")
    app_login(client, device="555")  # gleiche Kennung: z. B. anderer Benutzer am selben PC
    owner = db.execute(
        "SELECT u.username FROM devices d JOIN users u ON u.id = d.user_id WHERE d.id = '555'"
    ).fetchone()[0]
    assert owner == "alice"


def test_known_address_is_not_locked_out_by_user_limit(client, db):
    lim = LoginLimiter(max_ip=100, max_user=3, window=900)
    for _ in range(3):
        lim.failure("203.0.113.9", "alice")  # jemand von außen
    assert lim.blocked("198.51.100.1", "alice")
    assert not lim.blocked("198.51.100.1", "alice", known_ip=True)

    assert not known_login_ip(db, "alice", "198.51.100.1")
    log_login(db, "alice", None, "app", "198.51.100.1", True)
    assert known_login_ip(db, "ALICE", "198.51.100.1")
    assert not known_login_ip(db, "alice", "203.0.113.9")


def test_known_address_limit_per_ip_still_applies():
    lim = LoginLimiter(max_ip=2, max_user=100, window=900)
    lim.failure("198.51.100.1", "alice")
    lim.failure("198.51.100.1", "alice")
    assert lim.blocked("198.51.100.1", "alice", known_ip=True)


def test_prune_removes_old_unowned_devices_only(client, db):
    old = now() - 40 * 86400
    db.execute(
        "INSERT INTO devices (id, created_at, last_seen_at) VALUES ('alt', ?, ?), ('neu', ?, ?)",
        (old, old, now(), now()),
    )
    db.execute(
        "INSERT INTO devices (id, user_id, created_at, last_seen_at)"
        " VALUES ('besitz', (SELECT id FROM users WHERE username = 'alice'), ?, ?)",
        (old, old),
    )
    prune(db, 365, 30)
    ids = {r[0] for r in db.execute("SELECT id FROM devices")}
    assert ids == {"neu", "besitz"}


def test_security_headers(client):
    resp = client.get("/login")
    assert "frame-ancestors 'none'" in resp.headers["content-security-policy"]
    assert resp.headers["x-frame-options"] == "DENY"
    assert resp.headers["x-content-type-options"] == "nosniff"
    assert client.get("/api/login-options").headers["x-frame-options"] == "DENY"
