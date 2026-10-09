from __future__ import annotations

import re
from dataclasses import replace

import pytest
from fastapi.testclient import TestClient

from rdapi.config import Settings
from rdapi.db import connect
from rdapi.main import create_app
from rdapi.security import create_user

ADMIN_PW = "admin-passwort-1"
USER_PW = "nutzer-passwort-1"


@pytest.fixture
def cfg(tmp_path) -> Settings:
    base = Settings.from_env()
    return replace(
        base,
        db_path=str(tmp_path / "test.sqlite3"),
        timezone="Europe/Berlin",
        cookie_secure=False,
        bootstrap_admin_user="admin",
        bootstrap_admin_password=ADMIN_PW,
        login_max_failures_ip=5,
        login_max_failures_user=5,
        backup_keep=0,  # keine Sicherung beim Start; Tests schalten sie gezielt ein
    )


@pytest.fixture
def client(cfg) -> TestClient:
    app = create_app(cfg)
    conn = connect(cfg.db_path)
    create_user(conn, "alice", USER_PW)
    conn.close()
    with TestClient(app) as c:
        yield c


@pytest.fixture
def db(cfg):
    conn = connect(cfg.db_path)
    yield conn
    conn.close()


def app_login(client: TestClient, username="alice", password=USER_PW, device="111222333"):
    resp = client.post(
        "/api/login",
        json={
            "username": username,
            "password": password,
            "id": device,
            "uuid": "dXVpZA==",
            "autoLogin": True,
            "type": "account",
            "deviceInfo": {"os": "windows", "type": "client", "name": "PC-Alice"},
        },
    )
    assert resp.status_code == 200, resp.text
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}


def web_login(client: TestClient, username="admin", password=ADMIN_PW) -> str:
    resp = client.post(
        "/login",
        data={"username": username, "password": password, "next": "/"},
        follow_redirects=False,
    )
    assert resp.status_code == 303, resp.text
    page = client.get("/account").text
    return re.search(r'name="csrf" value="([^"]+)"', page).group(1)
