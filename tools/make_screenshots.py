# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Schnuecks
"""Erzeugt die Screenshots für README und Dokumentation (docs/screenshots/*.png).

    pip install -r requirements-dev.txt playwright && python -m playwright install chromium
    python tools/make_screenshots.py

Legt eine Demo-Datenbank mit erfundenen Geräten, Verbindungen und Adressbuch an, startet
RDAPI auf Englisch im dunklen Design und fotografiert die wichtigsten Seiten.

    python tools/make_screenshots.py --serve 8770

startet nur den Server mit den Demo-Daten (Anmeldung: admin / demo-password-1).
"""

from __future__ import annotations

import argparse
import json
import socket
import sys
import tempfile
import threading
import time
from dataclasses import replace
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
OUT = ROOT / "docs" / "screenshots"

ADMIN = ("admin", "demo-password-1")
HOUR = 3600

DEVICES = [
    # id, Besitzer, Name, Systembenutzer, Betriebssystem, CPU, RAM, zuletzt gesehen vor (s)
    (
        "123456789",
        "admin",
        "Office-PC",
        "alex",
        "windows / Windows 11 Pro",
        "AMD Ryzen 7 5700G, 3.8GHz, 16/8 cores",
        "32GB",
        20,
    ),
    (
        "234567891",
        "admin",
        "Media-Server",
        "root",
        "linux / Debian GNU/Linux 12",
        "Intel N100, 0.8GHz, 4/4 cores",
        "16GB",
        25,
    ),
    (
        "345678912",
        "sam",
        "Laptop-Sam",
        "sam",
        "windows / Windows 11 Home",
        "Intel Core i5-1235U, 1.3GHz, 12/10 cores",
        "16GB",
        40,
    ),
    (
        "456789123",
        "sam",
        "MacBook",
        "sam",
        "macos / macOS 15.4",
        "Apple M3, 8 cores",
        "16GB",
        3 * 86400,
    ),
    (
        "567891234",
        "admin",
        "Parents-PC",
        "mum",
        "windows / Windows 10 Home",
        "Intel Core i3-10100, 3.6GHz, 8/4 cores",
        "8GB",
        2 * HOUR,
    ),
]

CONNECTIONS = [
    # Gerät, Gegenstelle, Name, Art, Anmeldung, vor (s), Dauer (s), angenommen
    ("567891234", "123456789", "Office-PC", 0, 3, 50 * 60, 23 * 60, True),
    ("234567891", "123456789", "Office-PC", 1, 3, 3 * HOUR, 4 * 60, True),
    ("123456789", "345678912", "Laptop-Sam", 0, 2, 5 * HOUR, 47 * 60, True),
    ("567891234", "345678912", "Laptop-Sam", 0, 1, 26 * HOUR, 12 * 60, True),
    ("234567891", "987654321", "", 0, 0, 30 * HOUR, 0, False),
    ("123456789", "456789123", "MacBook", 4, 3, 2 * 86400, 6 * 60, True),
    ("567891234", "123456789", "Office-PC", 0, 3, 4 * 86400, 35 * 60, True),
]

TAGS = [("Family", 0xFF4C9A2A), ("Office", 0xFF2F80ED), ("Servers", 0xFFE4572E)]
PEERS = [
    {
        "id": "567891234",
        "alias": "Parents",
        "hostname": "Parents-PC",
        "username": "mum",
        "platform": "Windows",
        "tags": ["Family"],
        "note": "Printer driver in C:\\Drivers",
    },
    {
        "id": "234567891",
        "alias": "Media server",
        "hostname": "Media-Server",
        "username": "root",
        "platform": "Linux",
        "tags": ["Servers"],
        "note": "",
    },
    {
        "id": "345678912",
        "alias": "Sam's laptop",
        "hostname": "Laptop-Sam",
        "username": "sam",
        "platform": "Windows",
        "tags": ["Family", "Office"],
        "note": "",
    },
    {
        "id": "678912345",
        "alias": "Reception",
        "hostname": "Front-Desk",
        "username": "office",
        "platform": "Windows",
        "tags": ["Office"],
        "note": "Only after 6 pm",
    },
]


def seed(db_path: str) -> None:
    from rdapi.api import add_tag, personal_ab, save_peer
    from rdapi.db import connect, init_db, now
    from rdapi.security import create_user, log_login

    init_db(db_path)
    conn = connect(db_path)
    ts = now()
    ids = {
        "admin": create_user(conn, ADMIN[0], ADMIN[1], is_admin=True, display_name="Alex"),
        "sam": create_user(conn, "sam", "demo-password-2", display_name="Sam"),
    }
    for dev_id, owner, name, user, os_, cpu, mem, ago in DEVICES:
        conn.execute(
            "INSERT INTO devices (id, uuid, user_id, hostname, username, os, cpu, memory,"
            " version, sysinfo, created_at, last_seen_at, last_ip)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, '1.5.0', ?, ?, ?, '192.0.2.10')",
            (
                dev_id,
                f"uuid-{dev_id}",
                ids[owner],
                name,
                user,
                os_,
                cpu,
                mem,
                json.dumps({"hostname": name, "os": os_, "cpu": cpu, "memory": mem}),
                ts - 60 * 86400,
                ts - ago,
            ),
        )
    for n, (dev, peer, peer_name, kind, auth, ago, dur, ok) in enumerate(CONNECTIONS, start=1):
        start = ts - ago
        conn.execute(
            "INSERT INTO connections (device_id, conn_id, session_id, ip, peer_id, peer_name,"
            " conn_type, primary_auth, started_at, authed_at, ended_at)"
            " VALUES (?, ?, '', ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                dev,
                n,
                "198.51.100.23",
                peer,
                peer_name,
                kind,
                auth or None,
                start,
                start + 5 if ok else None,
                start + 5 + dur if ok else start + 30,
            ),
        )
    guid = personal_ab(conn, ids["admin"])
    for name, color in TAGS:
        add_tag(conn, guid, name, color)
    for peer in PEERS:
        save_peer(conn, guid, peer)
    for ago, user, src, ok in (
        (20 * 60, "admin", "web", True),
        (50 * 60, "admin", "app", True),
        (5 * HOUR, "sam", "app", True),
        (6 * HOUR, "sam", "app", False),
    ):
        conn.execute(
            "INSERT INTO login_events (username, user_id, source, ip, success, detail, created_at)"
            " VALUES (?, ?, ?, '198.51.100.23', ?, ?, ?)",
            (
                user,
                ids[user] if ok else None,
                src,
                int(ok),
                "client Office-PC (windows)" if src == "app" else "",
                ts - ago,
            ),
        )
    log_login(conn, "admin", ids["admin"], "web", "198.51.100.23", True)
    conn.close()


def start_server(db_path: str, port: int):
    import uvicorn

    from rdapi.config import Settings
    from rdapi.main import create_app

    cfg = replace(
        Settings.from_env(),
        db_path=db_path,
        cookie_secure=False,
        backup_keep=3,
        timezone="Europe/Berlin",
    )
    server = uvicorn.Server(
        uvicorn.Config(create_app(cfg), host="127.0.0.1", port=port, log_level="warning")
    )
    return server


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def shoot(url: str) -> None:
    from playwright.sync_api import sync_playwright

    OUT.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(
            viewport={"width": 1400, "height": 700}, locale="en-US", color_scheme="dark"
        )
        page.goto(f"{url}/login")
        page.fill("input[name=username]", ADMIN[0])
        page.fill("input[name=password]", ADMIN[1])
        page.click("form.login-form button[type=submit]")
        page.wait_for_url(f"{url}/")
        for name, path in (
            ("devices", "/"),
            ("device", "/devices/123456789"),
            ("history", "/history"),
            ("address-book", "/address-book"),
            ("users", "/users"),
            ("account", "/account"),
        ):
            page.goto(url + path)
            page.screenshot(path=OUT / f"{name}.png")
            print("saved", OUT / f"{name}.png")
        browser.close()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--serve", type=int, help="only run the demo server on this port")
    args = parser.parse_args()
    folder = Path(tempfile.mkdtemp(prefix="rdapi-demo-"))
    db_path = str(folder / "rdapi.sqlite3")
    seed(db_path)
    if args.serve:
        print(f"Demo: http://127.0.0.1:{args.serve}  ({ADMIN[0]} / {ADMIN[1]})")
        start_server(db_path, args.serve).run()
        return
    server = start_server(db_path, free_port())
    threading.Thread(target=server.run, daemon=True).start()
    while not server.started:
        time.sleep(0.05)
    try:
        shoot(f"http://127.0.0.1:{server.config.port}")
    finally:
        server.should_exit = True


if __name__ == "__main__":
    main()
