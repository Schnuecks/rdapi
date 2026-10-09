"""Die HTTP-Schnittstelle, die der RustDesk-Client (App 1.5.x) aufruft.

Wichtige Eigenheiten des Clients:
- Fehler stehen als {"error": "..."} im Body.
- Ändernde Adressbuch-Aufrufe und Audits gelten nur bei leerem Body als
  erfolgreich; jeder andere Body wird als Fehler angezeigt bzw. erneut gesendet.
- HTTP 401 meldet den Benutzer in der App ab.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from typing import Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, PlainTextResponse, Response

from . import oidc
from .config import Settings
from .db import now, transaction
from .deps import (
    client_ip,
    device_limiter,
    get_db,
    limiter,
    public_limiter,
    report_limiter,
    settings,
)
from .security import (
    LoginLimiter,
    RateLimiter,
    authenticate,
    finish_pending_login,
    issue_token,
    known_login_ip,
    log_login,
    resolve_pending_login,
    resolve_token,
    revoke_token,
    start_pending_login,
    token_hash,
    use_recovery_code,
)
from .totp import verify_user_code

router = APIRouter(prefix="/api")

MAX_BODY = 2 * 1024 * 1024
MAX_PEER_JSON = 16 * 1024
MAX_SYSINFO_JSON = 16 * 1024
MAX_AB_PEERS = 5000


class ApiError(Exception):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


def api_error_response(_: Request, exc: ApiError) -> JSONResponse:
    return JSONResponse({"error": exc.message}, status_code=exc.status)


def ok() -> Response:
    """Leere 200-Antwort: so erkennt der Client Erfolg."""
    return Response(status_code=200)


async def body_json(request: Request) -> Any:
    length = request.headers.get("content-length")
    if length and length.isdigit() and int(length) > MAX_BODY:
        raise ApiError(413, "Request too large.")
    raw = await request.body()
    if len(raw) > MAX_BODY:
        raise ApiError(413, "Request too large.")
    if not raw.strip():
        return None
    try:
        return json.loads(raw)
    except ValueError as exc:
        raise ApiError(400, "Invalid JSON.") from exc


async def body_dict(request: Request) -> dict[str, Any]:
    data = await body_json(request)
    return data if isinstance(data, dict) else {}


def text(value: Any, limit: int = 255) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        value = str(value)
    return value.strip()[:limit]


def as_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def paging(request: Request) -> tuple[int, int]:
    current = as_int(request.query_params.get("current")) or 1
    size = as_int(request.query_params.get("pageSize")) or 100
    current = max(current, 1)
    size = min(max(size, 1), 1000)
    return (current - 1) * size, size


def user_payload(user: sqlite3.Row) -> dict[str, Any]:
    return {
        "name": user["username"],
        "display_name": user["display_name"],
        "email": user["email"],
        "note": user["note"],
        "status": 1 if user["enabled"] else 0,
        "is_admin": bool(user["is_admin"]),
        # Der Rust-Teil des Clients erwartet das Feld zwingend.
        "info": {},
    }


def bearer(request: Request) -> str:
    header = request.headers.get("authorization", "")
    scheme, _, token = header.partition(" ")
    return token.strip() if scheme.lower() == "bearer" else ""


def current_user(
    request: Request,
    conn: sqlite3.Connection = Depends(get_db),
    cfg: Settings = Depends(settings),
) -> sqlite3.Row:
    user = resolve_token(conn, bearer(request), "app", cfg.app_token_days * 86400)
    if user is None:
        raise ApiError(401, "Not logged in or session expired.")
    return user


# --------------------------------------------------------------------------
# Anmeldung
# --------------------------------------------------------------------------


def _client_info(data: dict[str, Any]) -> str:
    info = data.get("deviceInfo") if isinstance(data.get("deviceInfo"), dict) else {}
    client_info = " ".join(
        part for part in (text(info.get("type"), 20), text(info.get("name"), 100)) if part
    )
    if text(info.get("os"), 100):
        client_info += f" ({text(info.get('os'), 100)})"
    return client_info


def device_matches(row: sqlite3.Row, device_uuid: str) -> bool:
    """Ob eine Meldung zu diesem Gerät gehört. Jedes Gerät schickt neben der RustDesk-ID
    eine interne Kennung mit; ist sie einmal gespeichert, muss sie passen."""
    return not row["uuid"] or row["uuid"] == device_uuid


def _claim_device(conn: sqlite3.Connection, user_id: int, data: dict[str, Any]) -> None:
    """Das Gerät, auf dem man sich anmeldet, gehört ab jetzt diesem Benutzer, aber nur,
    wenn es noch niemandem gehört oder seine Kennung passt. Sonst könnte man mit einer
    fremden ID dessen Verbindungsverlauf übernehmen."""
    device_id = text(data.get("id"), 64)
    device_uuid = text(data.get("uuid"), 128)
    if not device_id:
        return
    info = data.get("deviceInfo") if isinstance(data.get("deviceInfo"), dict) else {}
    row = conn.execute("SELECT uuid, user_id FROM devices WHERE id = ?", (device_id,)).fetchone()
    if row is None:
        conn.execute(
            "INSERT INTO devices (id, uuid, user_id, hostname, os, created_at)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (
                device_id,
                device_uuid,
                user_id,
                text(info.get("name"), 255),
                text(info.get("os"), 255),
                now(),
            ),
        )
    elif row["user_id"] is None or (device_uuid and row["uuid"] == device_uuid):
        conn.execute(
            "UPDATE devices SET user_id = ?,"
            " uuid = CASE WHEN uuid = '' THEN ? ELSE uuid END WHERE id = ?",
            (user_id, device_uuid, device_id),
        )


def _finish_login(
    conn: sqlite3.Connection,
    cfg: Settings,
    user: sqlite3.Row,
    data: dict[str, Any],
    ip: str,
    client_info: str,
    detail: str = "",
) -> dict[str, Any]:
    token, _ = issue_token(
        conn,
        user["id"],
        "app",
        cfg.app_token_days * 86400,
        device_id=text(data.get("id"), 64),
        device_uuid=text(data.get("uuid"), 128),
        client_info=client_info,
        ip=ip,
    )
    _claim_device(conn, user["id"], data)
    conn.execute("UPDATE users SET last_login_at = ? WHERE id = ?", (now(), user["id"]))
    log_login(conn, user["username"], user["id"], "app", ip, True, detail or client_info)
    return {"type": "access_token", "access_token": token, "user": user_payload(user)}


@router.post("/login")
async def login(
    request: Request,
    conn: sqlite3.Connection = Depends(get_db),
    cfg: Settings = Depends(settings),
    lim: LoginLimiter = Depends(limiter),
) -> dict[str, Any]:
    data = await body_dict(request)
    kind = text(data.get("type"))
    if kind not in ("", "account", "email_code"):
        raise ApiError(400, "This login type is not supported.")
    username = text(data.get("username"), 64)
    ip = client_ip(request)
    client_info = _client_info(data)

    if lim.blocked(ip, username, known_ip=known_login_ip(conn, username, ip)):
        if lim.log_block(ip):
            log_login(conn, username, None, "app", ip, False, "blocked (too many failures)")
        raise ApiError(429, "Too many failed logins. Please try again later.")

    if kind == "email_code":
        # Zweiter Schritt: Code aus der Authenticator-App zum Geheimnis aus Schritt eins.
        secret = text(data.get("secret"), 200)
        if not secret:
            raise ApiError(400, "The verification step is missing. Please sign in again.")
        code = text(data.get("tfaCode") or data.get("verificationCode"), 32)
        with transaction(conn):
            user = resolve_pending_login(conn, secret, "app")
            if user is not None and user["username"].lower() != username.lower():
                user = None
            if user is not None and (
                verify_user_code(conn, user, code, cfg.secret_key)
                or use_recovery_code(conn, user["id"], code)
            ):
                finish_pending_login(conn, user["p_id"])
                result = _finish_login(conn, cfg, user, data, ip, client_info, "2FA")
            else:
                log_login(conn, username, None, "app", ip, False, "wrong 2FA code")
                result = None
        if result is None:
            lim.failure(ip, username)
            raise ApiError(401, "Wrong verification code.")
        lim.success(ip, username)
        return result

    password = data.get("password")
    password = password if isinstance(password, str) else ""
    with transaction(conn):
        user = authenticate(conn, username, password) if username and password else None
        if user is None:
            log_login(conn, username, None, "app", ip, False, client_info)
            result = None
        elif user["totp_enabled"]:
            # Passwort stimmt; die App fragt jetzt nach dem Code (Antworttyp der App).
            result = {
                "type": "email_check",
                "tfa_type": "tfa_check",
                "secret": start_pending_login(conn, user["id"], "app"),
                # Vor dem zweiten Faktor nur der Name; den braucht die App für Schritt zwei.
                "user": {"name": user["username"]},
            }
        else:
            result = _finish_login(conn, cfg, user, data, ip, client_info)

    if user is None:
        lim.failure(ip, username)
        raise ApiError(401, "Wrong username or password.")
    if result["type"] == "access_token":
        lim.success(ip, username)
    return result


@router.get("/login-options")
def login_options(cfg: Settings = Depends(settings)) -> list[str]:
    # Die App zeigt für jeden Eintrag „oidc/<Name>“ einen Knopf „Mit <Name> anmelden“.
    return [f"oidc/{cfg.oidc_name}"] if cfg.oidc_enabled else []


# Anmeldung über den Anbieter aus der App: Die App holt sich eine Adresse, öffnet sie im
# Browser und fragt dann jede Sekunde nach, ob die Anmeldung dort bestätigt wurde.
NOT_YET = "No authed oidc is found"  # genau dieser Text: die App fragt dann weiter nach


@router.post("/oidc/auth")
async def oidc_auth(
    request: Request,
    conn: sqlite3.Connection = Depends(get_db),
    cfg: Settings = Depends(settings),
    flows: RateLimiter = Depends(public_limiter),
) -> dict[str, str]:
    if not cfg.oidc_enabled:
        raise ApiError(400, "Single sign-on is not set up.")
    data = await body_dict(request)
    if not flows.allow(f"start:{client_ip(request)}"):
        raise ApiError(429, "Too many sign-in attempts. Please try again later.")
    try:
        url, _state, code = oidc.start_flow(
            conn,
            cfg,
            str(request.base_url),
            "app",
            device_id=text(data.get("id"), 64),
            device_uuid=text(data.get("uuid"), 128),
            client_info=_client_info(data),
        )
    except oidc.OidcError as exc:
        raise ApiError(502, str(exc)) from exc
    return {"code": code, "url": url}


@router.get("/oidc/auth-query")
def oidc_auth_query(
    request: Request,
    code: str = "",
    id: str = "",
    uuid: str = "",
    conn: sqlite3.Connection = Depends(get_db),
    cfg: Settings = Depends(settings),
) -> Response:
    with transaction(conn):
        flow = conn.execute(
            "SELECT * FROM oidc_flows WHERE app_code_hash = ? AND kind = 'app'",
            (token_hash(code),),
        ).fetchone()
        if flow is None or flow["expires_at"] < now() or flow["device_id"] != text(id, 64):
            return JSONResponse({"error": "The sign-in has expired. Please sign in again."})
        if not flow["confirmed"]:
            return JSONResponse({"error": NOT_YET})
        user = conn.execute(
            "SELECT * FROM users WHERE id = ? AND enabled = 1", (flow["user_id"],)
        ).fetchone()
        conn.execute("DELETE FROM oidc_flows WHERE id = ?", (flow["id"],))
        if user is None:
            return JSONResponse({"error": "Your account is disabled."})
        data = {"id": flow["device_id"], "uuid": flow["device_uuid"] or text(uuid, 128)}
        result = _finish_login(
            conn, cfg, user, data, client_ip(request), flow["client_info"], "SSO"
        )
    return JSONResponse(result)


@router.post("/logout")
def logout(request: Request, conn: sqlite3.Connection = Depends(get_db)) -> Response:
    token = bearer(request)
    if token:
        revoke_token(conn, token)
    return ok()


@router.post("/currentUser")
def current_user_info(user: sqlite3.Row = Depends(current_user)) -> dict[str, Any]:
    return user_payload(user)


# --------------------------------------------------------------------------
# Geräte: Heartbeat und Sysinfo (ohne Anmeldung, Zuordnung über die ID)
# --------------------------------------------------------------------------


@router.post("/heartbeat")
async def heartbeat(
    request: Request,
    conn: sqlite3.Connection = Depends(get_db),
    reports: RateLimiter = Depends(report_limiter),
) -> dict:
    if not reports.allow(client_ip(request)):
        raise ApiError(429, "Too many requests. Please try again later.")
    data = await body_dict(request)
    device_id = text(data.get("id"), 64)
    device_uuid = text(data.get("uuid"), 128)
    if not device_id:
        return {}
    row = conn.execute("SELECT uuid FROM devices WHERE id = ?", (device_id,)).fetchone()
    if row is None:
        # Unbekanntes Gerät: Client soll seine Systeminfos (erneut) senden.
        return {"sysinfo": True}
    if not device_matches(row, device_uuid):
        # Gleiche ID, andere Kennung: nicht dieses Gerät, nichts ändern.
        return {}
    conn.execute(
        "UPDATE devices SET last_seen_at = ?, last_ip = ?,"
        " uuid = CASE WHEN uuid = '' THEN ? ELSE uuid END WHERE id = ?",
        (now(), client_ip(request), device_uuid, device_id),
    )
    return {}


@router.post("/sysinfo")
async def sysinfo(
    request: Request,
    conn: sqlite3.Connection = Depends(get_db),
    reports: RateLimiter = Depends(report_limiter),
    new_devices: RateLimiter = Depends(device_limiter),
) -> Response:
    if not reports.allow(client_ip(request)):
        raise ApiError(429, "Too many requests. Please try again later.")
    data = await body_dict(request)
    device_id = text(data.get("id"), 64)
    if not device_id:
        return PlainTextResponse("INVALID")
    raw = json.dumps(data, ensure_ascii=False)
    if len(raw) > MAX_SYSINFO_JSON:
        raw = "{}"
    fields = {
        "uuid": text(data.get("uuid"), 128),
        "hostname": text(data.get("hostname")),
        "username": text(data.get("username")),
        "os": text(data.get("os")),
        "cpu": text(data.get("cpu")),
        "memory": text(data.get("memory"), 32),
        "version": text(data.get("version"), 32),
    }
    ip = client_ip(request)
    ts = now()
    with transaction(conn):
        row = conn.execute("SELECT uuid FROM devices WHERE id = ?", (device_id,)).fetchone()
        if row is None:
            # Neue Geräte je Adresse begrenzen, sonst ließe sich die Datenbank mit
            # erfundenen Geräten füllen.
            if not new_devices.allow(f"ip:{ip}"):
                raise ApiError(429, "Too many new devices. Please try again later.")
            conn.execute(
                "INSERT INTO devices (id, uuid, hostname, username, os, cpu, memory, version,"
                " sysinfo, created_at, last_seen_at, last_ip)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (device_id, *fields.values(), raw, ts, ts, ip),
            )
        elif device_matches(row, fields["uuid"]):
            conn.execute(
                "UPDATE devices SET uuid = CASE WHEN uuid = '' THEN ? ELSE uuid END,"
                " hostname = ?, username = ?, os = ?, cpu = ?, memory = ?, version = ?,"
                " sysinfo = ?, last_seen_at = ?, last_ip = ? WHERE id = ?",
                (*fields.values(), raw, ts, ip, device_id),
            )
        else:
            # Fremde Kennung: die Angaben des echten Geräts nicht überschreiben.
            return PlainTextResponse("INVALID")
    return PlainTextResponse("SYSINFO_UPDATED")


@router.post("/sysinfo_ver")
def sysinfo_ver() -> Response:
    return PlainTextResponse("")


# --------------------------------------------------------------------------
# Verbindungsverlauf (Audit)
# --------------------------------------------------------------------------


def _claim_nonce(conn: sqlite3.Connection, data: dict[str, Any]) -> bool:
    """False, wenn dieser Datensatz schon gespeichert wurde (Wiederholung)."""
    nonce = text(data.get("nonce"), 100)
    if not nonce:
        return True
    try:
        conn.execute("INSERT INTO seen_nonces (nonce, created_at) VALUES (?, ?)", (nonce, now()))
    except sqlite3.IntegrityError:
        return False
    return True


def _known_device(conn: sqlite3.Connection, data: dict[str, Any]) -> bool:
    """Verlauf nur von Geräten annehmen, die sich gemeldet haben und deren Kennung passt."""
    device_id = text(data.get("id"), 64)
    row = conn.execute("SELECT uuid FROM devices WHERE id = ?", (device_id,)).fetchone()
    return row is not None and device_matches(row, text(data.get("uuid"), 128))


@router.post("/audit/conn")
async def audit_conn(
    request: Request,
    conn: sqlite3.Connection = Depends(get_db),
    reports: RateLimiter = Depends(report_limiter),
) -> Response:
    if not reports.allow(client_ip(request)):
        raise ApiError(429, "Too many requests. Please try again later.")
    data = await body_dict(request)
    device_id = text(data.get("id"), 64)
    conn_id = as_int(data.get("conn_id"))
    # Leere Antwort auch beim Verwerfen, sonst sendet der Client immer wieder.
    if not device_id or conn_id is None or not _known_device(conn, data):
        return ok()
    action = text(data.get("action"), 20)
    session_id = text(data.get("session_id"), 32)
    ts = now()
    with transaction(conn):
        if not _claim_nonce(conn, data):
            return ok()
        if action == "new":
            conn.execute(
                "INSERT INTO connections (device_id, conn_id, session_id, ip, started_at)"
                " VALUES (?, ?, ?, ?, ?)",
                (device_id, conn_id, session_id, text(data.get("ip"), 64), ts),
            )
            return ok()
        row = conn.execute(
            "SELECT id FROM connections WHERE device_id = ? AND conn_id = ? AND ended_at IS NULL"
            " ORDER BY id DESC LIMIT 1",
            (device_id, conn_id),
        ).fetchone()
        if row is None:
            cur = conn.execute(
                "INSERT INTO connections (device_id, conn_id, session_id, started_at)"
                " VALUES (?, ?, ?, ?)",
                (device_id, conn_id, session_id, ts),
            )
            row_id = cur.lastrowid
        else:
            row_id = row["id"]
        peer = data.get("peer")
        if isinstance(peer, list | tuple) and peer:
            conn.execute(
                "UPDATE connections SET peer_id = ?, peer_name = ?, conn_type = ?,"
                " primary_auth = ?, authed_at = ?,"
                " session_id = CASE WHEN ? NOT IN ('', '0') THEN ? ELSE session_id END"
                " WHERE id = ?",
                (
                    text(peer[0], 64),
                    text(peer[1] if len(peer) > 1 else "", 255),
                    as_int(data.get("type")),
                    as_int(data.get("primary_auth")),
                    ts,
                    session_id,
                    session_id,
                    row_id,
                ),
            )
        if action == "close":
            conn.execute("UPDATE connections SET ended_at = ? WHERE id = ?", (ts, row_id))
    return ok()


@router.post("/audit/{kind}")
async def audit_other(
    kind: str,
    request: Request,
    conn: sqlite3.Connection = Depends(get_db),
    reports: RateLimiter = Depends(report_limiter),
) -> Response:
    if not reports.allow(client_ip(request)):
        raise ApiError(429, "Too many requests. Please try again later.")
    if kind not in ("file", "alarm"):
        raise ApiError(404, "Unknown audit type.")
    data = await body_dict(request)
    if not _known_device(conn, data):
        return ok()
    payload = json.dumps(data, ensure_ascii=False)[:MAX_SYSINFO_JSON]
    with transaction(conn):
        if _claim_nonce(conn, data):
            conn.execute(
                "INSERT INTO audit_events (kind, device_id, payload, created_at)"
                " VALUES (?, ?, ?, ?)",
                (kind, text(data.get("id"), 64), payload, now()),
            )
    return ok()


# --------------------------------------------------------------------------
# Benutzer- und Geräteliste (Reiter „Gruppe“ / „Zugängliche Geräte“)
# --------------------------------------------------------------------------


def _accessible_user_ids(conn: sqlite3.Connection, user: sqlite3.Row) -> list[int]:
    if user["is_admin"]:
        return [r["id"] for r in conn.execute("SELECT id FROM users WHERE enabled = 1")]
    return [user["id"]]


@router.get("/users")
def users(
    request: Request,
    conn: sqlite3.Connection = Depends(get_db),
    user: sqlite3.Row = Depends(current_user),
) -> dict[str, Any]:
    ids = _accessible_user_ids(conn, user)
    offset, limit = paging(request)
    marks = ",".join("?" * len(ids))
    rows = conn.execute(
        f"SELECT * FROM users WHERE id IN ({marks}) ORDER BY username LIMIT ? OFFSET ?",
        (*ids, limit, offset),
    ).fetchall()
    return {"total": len(ids), "data": [user_payload(r) for r in rows]}


@router.get("/peers")
def peers(
    request: Request,
    conn: sqlite3.Connection = Depends(get_db),
    user: sqlite3.Row = Depends(current_user),
) -> dict[str, Any]:
    ids = _accessible_user_ids(conn, user)
    offset, limit = paging(request)
    marks = ",".join("?" * len(ids))
    total = conn.execute(
        f"SELECT COUNT(*) FROM devices WHERE user_id IN ({marks})", ids
    ).fetchone()[0]
    rows = conn.execute(
        "SELECT d.*, u.username AS owner FROM devices d JOIN users u ON u.id = d.user_id"
        f" WHERE d.user_id IN ({marks}) ORDER BY d.id LIMIT ? OFFSET ?",
        (*ids, limit, offset),
    ).fetchall()
    data = [
        {
            "id": r["id"],
            "info": {"username": r["username"], "os": r["os"], "device_name": r["hostname"]},
            "status": 1,
            "user": r["owner"],
            "user_name": r["owner"],
            "note": r["note"],
            "device_group_name": "",
        }
        for r in rows
    ]
    return {"total": total, "data": data}


@router.get("/device-group/accessible")
def device_groups(_: sqlite3.Row = Depends(current_user)) -> dict[str, Any]:
    return {"total": 0, "data": []}


# --------------------------------------------------------------------------
# Adressbuch
# --------------------------------------------------------------------------


def personal_ab(conn: sqlite3.Connection, user_id: int) -> str:
    row = conn.execute("SELECT guid FROM address_books WHERE user_id = ?", (user_id,)).fetchone()
    if row:
        return row["guid"]
    guid = str(uuid.uuid4())
    conn.execute(
        "INSERT OR IGNORE INTO address_books (guid, user_id, created_at) VALUES (?, ?, ?)",
        (guid, user_id, now()),
    )
    return conn.execute("SELECT guid FROM address_books WHERE user_id = ?", (user_id,)).fetchone()[
        "guid"
    ]


def own_ab(conn: sqlite3.Connection, user: sqlite3.Row, guid: str) -> str:
    if not guid or guid != personal_ab(conn, user["id"]):
        raise ApiError(403, "No access to this address book.")
    return guid


def load_peer(conn: sqlite3.Connection, guid: str, peer_id: str) -> dict[str, Any] | None:
    row = conn.execute(
        "SELECT data FROM ab_peers WHERE ab_guid = ? AND peer_id = ?", (guid, peer_id)
    ).fetchone()
    return json.loads(row["data"]) if row else None


def save_peer(conn: sqlite3.Connection, guid: str, peer: dict[str, Any]) -> None:
    raw = json.dumps(peer, ensure_ascii=False)
    if len(raw) > MAX_PEER_JSON:
        raise ApiError(400, "Entry too large.")
    conn.execute(
        "INSERT INTO ab_peers (ab_guid, peer_id, data, position, updated_at)"
        " VALUES (?, ?, ?, (SELECT COALESCE(MAX(position), 0) + 1 FROM ab_peers WHERE ab_guid = ?),"
        " ?) ON CONFLICT(ab_guid, peer_id) DO UPDATE SET data = excluded.data,"
        " updated_at = excluded.updated_at",
        (guid, peer["id"], raw, guid, now()),
    )


def _peer_from_body(data: Any) -> dict[str, Any]:
    if not isinstance(data, dict):
        raise ApiError(400, "Invalid entry.")
    peer_id = text(data.get("id"), 64)
    if not peer_id:
        raise ApiError(400, "The ID is missing.")
    peer = dict(data)
    peer["id"] = peer_id
    if "tags" in peer and not isinstance(peer["tags"], list):
        peer["tags"] = []
    return peer


def _tag_from_body(data: Any) -> tuple[str, int]:
    if not isinstance(data, dict):
        raise ApiError(400, "Invalid tag.")
    name = text(data.get("name"), 100)
    if not name:
        raise ApiError(400, "The tag name is missing.")
    color = as_int(data.get("color")) or 0
    return name, color


def add_tag(conn: sqlite3.Connection, guid: str, name: str, color: int) -> None:
    conn.execute(
        "INSERT INTO ab_tags (ab_guid, name, color, position) VALUES (?, ?, ?,"
        " (SELECT COALESCE(MAX(position), 0) + 1 FROM ab_tags WHERE ab_guid = ?))"
        " ON CONFLICT(ab_guid, name) DO UPDATE SET color = excluded.color",
        (guid, name, color, guid),
    )


def rewrite_peer_tags(conn: sqlite3.Connection, guid: str, change) -> None:
    """Wendet change(tags) -> tags auf alle Einträge an, deren Tags sich ändern."""
    for row in conn.execute(
        "SELECT peer_id, data FROM ab_peers WHERE ab_guid = ?", (guid,)
    ).fetchall():
        peer = json.loads(row["data"])
        tags = peer.get("tags")
        if not isinstance(tags, list):
            continue
        new_tags = change(tags)
        if new_tags != tags:
            peer["tags"] = new_tags
            save_peer(conn, guid, peer)


@router.post("/ab/settings")
def ab_settings(_: sqlite3.Row = Depends(current_user)) -> dict[str, Any]:
    return {"max_peer_one_ab": 0}


@router.post("/ab/personal")
def ab_personal(
    conn: sqlite3.Connection = Depends(get_db), user: sqlite3.Row = Depends(current_user)
) -> dict[str, Any]:
    return {"guid": personal_ab(conn, user["id"])}


@router.post("/ab/shared/profiles")
def ab_shared_profiles(_: sqlite3.Row = Depends(current_user)) -> dict[str, Any]:
    return {"total": 0, "data": []}


@router.post("/ab/peers")
def ab_peers(
    request: Request,
    conn: sqlite3.Connection = Depends(get_db),
    user: sqlite3.Row = Depends(current_user),
) -> dict[str, Any]:
    guid = own_ab(conn, user, request.query_params.get("ab", ""))
    offset, limit = paging(request)
    total = conn.execute("SELECT COUNT(*) FROM ab_peers WHERE ab_guid = ?", (guid,)).fetchone()[0]
    rows = conn.execute(
        "SELECT data FROM ab_peers WHERE ab_guid = ? ORDER BY position LIMIT ? OFFSET ?",
        (guid, limit, offset),
    ).fetchall()
    return {"total": total, "data": [json.loads(r["data"]) for r in rows]}


@router.post("/ab/tags/{guid}")
def ab_tags(
    guid: str,
    conn: sqlite3.Connection = Depends(get_db),
    user: sqlite3.Row = Depends(current_user),
) -> list[dict[str, Any]]:
    own_ab(conn, user, guid)
    rows = conn.execute(
        "SELECT name, color FROM ab_tags WHERE ab_guid = ? ORDER BY position", (guid,)
    ).fetchall()
    return [{"name": r["name"], "color": r["color"]} for r in rows]


@router.post("/ab/peer/add/{guid}")
async def ab_peer_add(
    guid: str,
    request: Request,
    conn: sqlite3.Connection = Depends(get_db),
    user: sqlite3.Row = Depends(current_user),
) -> Response:
    own_ab(conn, user, guid)
    peer = _peer_from_body(await body_json(request))
    with transaction(conn):
        save_peer(conn, guid, peer)
    return ok()


@router.put("/ab/peer/update/{guid}")
async def ab_peer_update(
    guid: str,
    request: Request,
    conn: sqlite3.Connection = Depends(get_db),
    user: sqlite3.Row = Depends(current_user),
) -> Response:
    own_ab(conn, user, guid)
    changes = _peer_from_body(await body_json(request))
    with transaction(conn):
        peer = load_peer(conn, guid, changes["id"])
        if peer is None:
            raise ApiError(400, "Entry not found.")
        peer.update(changes)
        save_peer(conn, guid, peer)
    return ok()


@router.delete("/ab/peer/{guid}")
async def ab_peer_delete(
    guid: str,
    request: Request,
    conn: sqlite3.Connection = Depends(get_db),
    user: sqlite3.Row = Depends(current_user),
) -> Response:
    own_ab(conn, user, guid)
    ids = await body_json(request)
    if not isinstance(ids, list):
        raise ApiError(400, "Expected a list of IDs.")
    with transaction(conn):
        for peer_id in ids:
            conn.execute(
                "DELETE FROM ab_peers WHERE ab_guid = ? AND peer_id = ?", (guid, text(peer_id, 64))
            )
    return ok()


@router.post("/ab/tag/add/{guid}")
async def ab_tag_add(
    guid: str,
    request: Request,
    conn: sqlite3.Connection = Depends(get_db),
    user: sqlite3.Row = Depends(current_user),
) -> Response:
    own_ab(conn, user, guid)
    name, color = _tag_from_body(await body_json(request))
    add_tag(conn, guid, name, color)
    return ok()


@router.put("/ab/tag/rename/{guid}")
async def ab_tag_rename(
    guid: str,
    request: Request,
    conn: sqlite3.Connection = Depends(get_db),
    user: sqlite3.Row = Depends(current_user),
) -> Response:
    own_ab(conn, user, guid)
    data = await body_dict(request)
    old, new = text(data.get("old"), 100), text(data.get("new"), 100)
    if not old or not new:
        raise ApiError(400, "Old and new name are required.")
    with transaction(conn):
        exists = conn.execute(
            "SELECT 1 FROM ab_tags WHERE ab_guid = ? AND name = ?", (guid, new)
        ).fetchone()
        if exists:
            raise ApiError(400, f"The tag {new} already exists.")
        cur = conn.execute(
            "UPDATE ab_tags SET name = ? WHERE ab_guid = ? AND name = ?", (new, guid, old)
        )
        if cur.rowcount == 0:
            raise ApiError(400, "Tag not found.")
        rewrite_peer_tags(conn, guid, lambda tags: [new if t == old else t for t in tags])
    return ok()


@router.put("/ab/tag/update/{guid}")
async def ab_tag_update(
    guid: str,
    request: Request,
    conn: sqlite3.Connection = Depends(get_db),
    user: sqlite3.Row = Depends(current_user),
) -> Response:
    own_ab(conn, user, guid)
    name, color = _tag_from_body(await body_json(request))
    cur = conn.execute(
        "UPDATE ab_tags SET color = ? WHERE ab_guid = ? AND name = ?", (color, guid, name)
    )
    if cur.rowcount == 0:
        raise ApiError(400, "Tag not found.")
    return ok()


@router.delete("/ab/tag/{guid}")
async def ab_tag_delete(
    guid: str,
    request: Request,
    conn: sqlite3.Connection = Depends(get_db),
    user: sqlite3.Row = Depends(current_user),
) -> Response:
    own_ab(conn, user, guid)
    names = await body_json(request)
    if not isinstance(names, list):
        raise ApiError(400, "Expected a list of tags.")
    names = {text(n, 100) for n in names}
    with transaction(conn):
        for name in names:
            conn.execute("DELETE FROM ab_tags WHERE ab_guid = ? AND name = ?", (guid, name))
        rewrite_peer_tags(conn, guid, lambda tags: [t for t in tags if t not in names])
    return ok()


# Altes Adressbuch-Format (ältere Clients): das ganze Buch als JSON-String.
# Es wird auf das persönliche Adressbuch abgebildet.


@router.get("/ab")
def legacy_ab_get(
    conn: sqlite3.Connection = Depends(get_db), user: sqlite3.Row = Depends(current_user)
) -> dict[str, Any]:
    guid = personal_ab(conn, user["id"])
    tags = conn.execute(
        "SELECT name, color FROM ab_tags WHERE ab_guid = ? ORDER BY position", (guid,)
    ).fetchall()
    peers = conn.execute(
        "SELECT data FROM ab_peers WHERE ab_guid = ? ORDER BY position", (guid,)
    ).fetchall()
    book = {
        "tags": [t["name"] for t in tags],
        "peers": [json.loads(p["data"]) for p in peers],
        "tag_colors": json.dumps({t["name"]: t["color"] for t in tags}),
    }
    return {"data": json.dumps(book, ensure_ascii=False)}


@router.post("/ab")
async def legacy_ab_post(
    request: Request,
    conn: sqlite3.Connection = Depends(get_db),
    user: sqlite3.Row = Depends(current_user),
) -> Response:
    body = await body_dict(request)
    try:
        book = json.loads(body.get("data") or "{}")
    except (TypeError, ValueError) as exc:
        raise ApiError(400, "Invalid address book.") from exc
    if not isinstance(book, dict):
        raise ApiError(400, "Invalid address book.")
    peers = [_peer_from_body(p) for p in book.get("peers") or []]
    if len(peers) > MAX_AB_PEERS:
        raise ApiError(400, "Too many entries.")
    tags = [text(t, 100) for t in book.get("tags") or [] if text(t, 100)]
    try:
        colors = json.loads(book.get("tag_colors") or "{}")
    except (TypeError, ValueError):
        colors = {}
    if not isinstance(colors, dict):
        colors = {}
    with transaction(conn):
        guid = personal_ab(conn, user["id"])
        conn.execute("DELETE FROM ab_peers WHERE ab_guid = ?", (guid,))
        conn.execute("DELETE FROM ab_tags WHERE ab_guid = ?", (guid,))
        for name in tags:
            add_tag(conn, guid, name, as_int(colors.get(name)) or 0)
        for peer in peers:
            save_peer(conn, guid, peer)
    return ok()
