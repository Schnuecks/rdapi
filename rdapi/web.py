"""Web UI (English and German) for devices, history, address book and users.

Läuft meist zusätzlich hinter einer Anmeldeseite des Reverse Proxys, hat aber eine
eigene Anmeldung mit den gleichen Zugangsdaten wie die App. So bleibt sie auch dann
geschützt, wenn eine Regel im Proxy einmal nicht greift.
"""

from __future__ import annotations

import json
import secrets
import shutil
import sqlite3
from pathlib import Path
from typing import Any
from urllib.parse import quote

from fastapi import APIRouter, Depends, File, Form, Request, UploadFile
from fastapi.responses import (
    FileResponse,
    HTMLResponse,
    JSONResponse,
    RedirectResponse,
    Response,
)
from fastapi.templating import Jinja2Templates

from . import __version__, backup, i18n, oidc, passkeys, secretbox
from .api import add_tag, load_peer, personal_ab, rewrite_peer_tags, save_peer
from .config import Settings
from .db import connect, now, transaction
from .deps import client_ip, get_db, limiter, public_limiter, settings
from .i18n import gettext as _
from .security import (
    LoginLimiter,
    RateLimiter,
    authenticate,
    clear_setup_code,
    create_user,
    disable_totp,
    finish_pending_login,
    has_passkeys,
    has_users,
    hash_password,
    issue_token,
    known_login_ip,
    log_activity,
    log_login,
    new_recovery_codes,
    password_problem,
    reset_second_factors,
    resolve_pending_login,
    resolve_token,
    revoke_token,
    second_factor_required,
    setup_code,
    setup_code_valid,
    start_pending_login,
    token_hash,
    unused_recovery_codes,
    use_recovery_code,
    username_problem,
)
from .totp import (
    format_secret,
    matching_step,
    new_secret,
    provisioning_uri,
    qr_svg,
    secret_of,
    verify_user_code,
)

COOKIE = "rdapi_session"
PAGE_SIZE = 50
ONE_YEAR = 365 * 86400
APP_REPO = "https://github.com/Schnuecks/rdapi"

router = APIRouter()
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))

CONN_TYPES = {
    0: "Remote control",
    1: "File transfer",
    2: "Port forwarding",
    3: "Camera",
    4: "Terminal",
}
PRIMARY_AUTH = {
    1: "Accepted by click",
    2: "One-time password",
    3: "Permanent password",
    4: "Switch sides",
}
MESSAGES = {
    "saved": "Saved.",
    "password": "The password has been changed.",
    "created": "The user has been created.",
    "deleted": "Deleted.",
    "ended": "The session has been ended.",
    "2fa_off": "Two-factor sign-in has been turned off.",
    "backup": "The backup has been created.",
    "restored": "The backup has been restored.",
    "uploaded": "The backup has been uploaded. You can now restore it.",
    "passkey": "The passkey has been added.",
}


class LoginRequired(Exception):
    pass


class Forbidden(Exception):
    pass


def setup_filters(tz: str) -> None:
    def dt(ts: int | None) -> str:
        return i18n.fmt_dt(ts, tz)

    def duration(row: sqlite3.Row) -> str:
        if not row["ended_at"]:
            return _("open")
        seconds = max(row["ended_at"] - (row["authed_at"] or row["started_at"]), 0)
        hours, rest = divmod(seconds, 3600)
        minutes, secs = divmod(rest, 60)
        if hours:
            return f"{hours} h {minutes} min"
        if minutes:
            return f"{minutes} min {secs} s"
        return f"{secs} s"

    def theme(request: Request) -> str:
        return i18n.pick_theme(request.cookies.get(i18n.THEME_COOKIE))

    def language_choice(request: Request) -> str | None:
        value = request.cookies.get(i18n.LANG_COOKIE)
        return value if value in i18n.LANGUAGES else None

    def current_url(request: Request) -> str:
        url = request.url.path
        return url + ("?" + request.url.query if request.url.query else "")

    templates.env.filters["dt"] = dt
    templates.env.filters["duration"] = duration
    templates.env.globals.update(
        _=_,
        lang=i18n.current,
        theme=theme,
        language_choice=language_choice,
        current_url=current_url,
        LANGUAGES=i18n.LANGUAGES,
        THEME_LABELS=i18n.THEME_LABELS,
        NEXT_THEME=i18n.NEXT_THEME,
        CONN_TYPES=CONN_TYPES,
        PRIMARY_AUTH=PRIMARY_AUTH,
        APP_VERSION=__version__,
        APP_REPO=APP_REPO,
    )


def web_user(
    request: Request,
    conn: sqlite3.Connection = Depends(get_db),
    cfg: Settings = Depends(settings),
) -> sqlite3.Row:
    user = resolve_token(
        conn,
        request.cookies.get(session_cookie(request, cfg), ""),
        "web",
        cfg.web_session_hours * 3600,
    )
    if user is None:
        raise LoginRequired
    return user


def admin_user(user: sqlite3.Row = Depends(web_user)) -> sqlite3.Row:
    if not user["is_admin"]:
        raise Forbidden
    return user


def check_csrf(user: sqlite3.Row, token: str) -> None:
    if not token or not secrets.compare_digest(user["t_csrf"], token):
        raise Forbidden


def render(
    request: Request,
    name: str,
    user: sqlite3.Row | None,
    status: int = 200,
    **ctx: Any,
) -> HTMLResponse:
    message = MESSAGES.get(request.query_params.get("ok", ""))
    cfg = request.app.state.settings
    ctx.update(
        user=user,
        csrf=user["t_csrf"] if user is not None else "",
        sso_name=cfg.oidc_name if cfg.oidc_enabled else "",
        passkey_login=name == "login.html" and _any_passkeys(cfg.db_path),
        message=_(message) if message else None,
        online_after=now() - cfg.online_seconds,
    )
    ctx.setdefault("error", None)
    return templates.TemplateResponse(request, name, ctx, status_code=status)


def redirect(url: str, ok: str | None = None) -> RedirectResponse:
    if ok:
        url += ("&" if "?" in url else "?") + f"ok={ok}"
    return RedirectResponse(url, status_code=303)


def login_redirect_handler(request: Request, _exc: LoginRequired) -> RedirectResponse:
    target = request.url.path
    if request.url.query:
        target += "?" + request.url.query
    return RedirectResponse(f"/login?next={quote(target)}", status_code=303)


def forbidden_handler(request: Request, _exc: Forbidden) -> HTMLResponse:
    return render(
        request, "error.html", None, status=403, text=_("You are not allowed to do that.")
    )


def safe_next(target: str) -> str:
    # Nur relative Pfade dieser Anwendung, keine fremden Ziele.
    if target.startswith("/") and not target.startswith("//") and "\\" not in target:
        return target
    return "/"


# --------------------------------------------------------------------------
# Anmeldung, Sprache und Design
# --------------------------------------------------------------------------


@router.get("/healthz")
def healthz(conn: sqlite3.Connection = Depends(get_db)) -> dict[str, str]:
    conn.execute("SELECT 1").fetchone()
    return {"status": "ok"}


@router.post("/appearance")
def appearance(
    lang: str | None = Form(None),
    theme: str | None = Form(None),
    next: str = Form("/"),
) -> Response:
    response = redirect(safe_next(next))
    if lang in i18n.LANGUAGES:
        response.set_cookie(i18n.LANG_COOKIE, lang, max_age=ONE_YEAR, samesite="lax")
    elif lang == "auto":
        response.delete_cookie(i18n.LANG_COOKIE)
    if theme in i18n.THEMES:
        response.set_cookie(i18n.THEME_COOKIE, theme, max_age=ONE_YEAR, samesite="lax")
    return response


def _start_session(
    request: Request,
    conn: sqlite3.Connection,
    cfg: Settings,
    user_id: int,
    target: str,
) -> Response:
    token, _csrf = issue_token(
        conn,
        user_id,
        "web",
        cfg.web_session_hours * 3600,
        client_info=request.headers.get("user-agent", "")[:200],
        ip=client_ip(request),
    )
    response = redirect(target)
    response.set_cookie(
        session_cookie(request, cfg),
        token,
        max_age=cfg.web_session_hours * 3600,
        httponly=True,
        secure=_cookie_secure(request, cfg),
        samesite="strict",
    )
    return response


def session_cookie(request: Request, cfg: Settings) -> str:
    """Über HTTPS mit dem Präfix __Host-: Der Browser nimmt das Cookie dann nur von genau
    dieser Adresse, nur über HTTPS und für alle Pfade an."""
    return f"__Host-{COOKIE}" if _cookie_secure(request, cfg) else COOKIE


def _cookie_secure(request: Request, cfg: Settings) -> bool:
    if cfg.cookie_secure is not None:
        return cfg.cookie_secure
    return request.url.scheme == "https"


# Erstes Admin-Konto über die Weboberfläche. Der Einrichtungscode aus dem
# Container-Log verhindert, dass jemand anderes das Konto vor dir anlegt.


@router.get("/setup", response_class=HTMLResponse)
def setup_form(request: Request, conn: sqlite3.Connection = Depends(get_db)) -> Response:
    if has_users(conn):
        return redirect("/")
    setup_code(conn)  # sicherstellen, dass es einen gibt (steht auch im Log)
    return render(request, "setup.html", None, username="")


@router.post("/setup")
def setup_submit(
    request: Request,
    code: str = Form(""),
    username: str = Form(""),
    password: str = Form(""),
    repeat: str = Form(""),
    conn: sqlite3.Connection = Depends(get_db),
    cfg: Settings = Depends(settings),
    lim: LoginLimiter = Depends(limiter),
) -> Response:
    if has_users(conn):
        return redirect("/")
    username = username.strip()
    ip = client_ip(request)

    def page(error: str, status: int) -> HTMLResponse:
        return render(request, "setup.html", None, status=status, username=username, error=error)

    if lim.blocked(ip, "setup"):
        return page(_("Too many failed attempts. Please try again later."), 429)
    if not setup_code_valid(conn, code):
        lim.failure(ip, "setup")
        return page(
            _("The setup code is wrong. You find it in the container log."),
            401,
        )
    problem = username_problem(username) or password_problem(password)
    if problem:
        return page(_(problem), 400)
    if password != repeat:
        return page(_("The passwords do not match."), 400)
    with transaction(conn):
        if has_users(conn):
            return redirect("/")
        user_id = create_user(conn, username, password, is_admin=True)
        clear_setup_code(conn)
        conn.execute("UPDATE users SET last_login_at = ? WHERE id = ?", (now(), user_id))
        log_login(conn, username, user_id, "web", ip, True, "setup")
        response = _start_session(request, conn, cfg, user_id, "/")
    lim.success(ip, "setup")
    return response


@router.get("/login", response_class=HTMLResponse)
def login_form(
    request: Request, next: str = "/", conn: sqlite3.Connection = Depends(get_db)
) -> Response:
    if not has_users(conn):
        return redirect("/setup")
    return render(request, "login.html", None, next=safe_next(next))


@router.post("/login")
def login_submit(
    request: Request,
    username: str = Form(""),
    password: str = Form(""),
    next: str = Form("/"),
    conn: sqlite3.Connection = Depends(get_db),
    cfg: Settings = Depends(settings),
    lim: LoginLimiter = Depends(limiter),
) -> Response:
    username = username.strip()[:64]
    ip = client_ip(request)
    target = safe_next(next)
    if lim.blocked(ip, username, known_ip=known_login_ip(conn, username, ip)):
        if lim.log_block(ip):
            log_login(conn, username, None, "web", ip, False, "blocked (too many failures)")
        error = _("Too many failed logins. Please try again later.")
        return render(request, "login.html", None, status=429, next=target, error=error)
    with transaction(conn):
        user = authenticate(conn, username, password) if username and password else None
        if user is None:
            log_login(conn, username, None, "web", ip, False)
        elif needs_second := second_factor_required(conn, user):
            pending = start_pending_login(conn, user["id"], "web")
        else:
            conn.execute("UPDATE users SET last_login_at = ? WHERE id = ?", (now(), user["id"]))
            log_login(conn, user["username"], user["id"], "web", ip, True)
            response = _start_session(request, conn, cfg, user["id"], target)
    if user is None:
        lim.failure(ip, username)
        error = _("Wrong username or password.")
        return render(request, "login.html", None, status=401, next=target, error=error)
    if needs_second:
        return _code_page(request, conn, user, pending, target)
    lim.success(ip, username)
    return response


def _code_page(
    request: Request,
    conn: sqlite3.Connection,
    user: sqlite3.Row,
    pending: str,
    target: str,
    error: str | None = None,
) -> HTMLResponse:
    """Zweiter Schritt: Code aus der App, Passkey oder Wiederherstellungscode."""
    return render(
        request,
        "login_code.html",
        None,
        status=401 if error else 200,
        pending=pending,
        next=target,
        totp=bool(user["totp_enabled"]),
        keys=has_passkeys(conn, user["id"]),
        error=error,
    )


@router.post("/login/code")
def login_code_submit(
    request: Request,
    pending: str = Form(""),
    code: str = Form(""),
    next: str = Form("/"),
    conn: sqlite3.Connection = Depends(get_db),
    cfg: Settings = Depends(settings),
    lim: LoginLimiter = Depends(limiter),
) -> Response:
    """Zweiter Schritt der Anmeldung: Code aus der Authenticator-App oder ein
    Wiederherstellungscode."""
    ip = client_ip(request)
    target = safe_next(next)
    with transaction(conn):
        user = resolve_pending_login(conn, pending, "web")
        if user is None:
            response = None
            expired = True
        else:
            expired = False
            totp_ok = user["totp_enabled"] and verify_user_code(conn, user, code, cfg.secret_key)
            if totp_ok or use_recovery_code(conn, user["id"], code):
                finish_pending_login(conn, user["p_id"])
                conn.execute("UPDATE users SET last_login_at = ? WHERE id = ?", (now(), user["id"]))
                log_login(conn, user["username"], user["id"], "web", ip, True, "2FA")
                response = _start_session(request, conn, cfg, user["id"], target)
            else:
                log_login(conn, user["username"], user["id"], "web", ip, False, "wrong 2FA code")
                response = None
    if expired:
        error = _("The sign-in has expired. Please sign in again.")
        return render(request, "login.html", None, status=401, next=target, error=error)
    if response is None:
        lim.failure(ip, user["username"])
        return _code_page(request, conn, user, pending, target, _("Wrong code. Please try again."))
    lim.success(ip, user["username"])
    return response


# --------------------------------------------------------------------------
# Anmeldung über einen OpenID-Connect-Anbieter
# --------------------------------------------------------------------------

OIDC_COOKIE = "rdapi_oidc"


def _login_error(request: Request, error: str, status: int = 401) -> HTMLResponse:
    return render(request, "login.html", None, status=status, next="/", error=_(error))


@router.get("/login/oidc")
def oidc_start(
    request: Request,
    next: str = "/",
    conn: sqlite3.Connection = Depends(get_db),
    cfg: Settings = Depends(settings),
    starts: RateLimiter = Depends(public_limiter),
) -> Response:
    if not cfg.oidc_enabled:
        return redirect("/login")
    if not starts.allow(f"start:{client_ip(request)}"):
        return _login_error(request, "Too many failed logins. Please try again later.", 429)
    try:
        url, state, _code = oidc.start_flow(
            conn, cfg, str(request.base_url), "web", next_url=safe_next(next)
        )
    except oidc.OidcError as exc:
        return _login_error(request, str(exc), 502)
    response = RedirectResponse(url, status_code=303)
    # Bindet den Rücksprung an diesen Browser; ohne könnte man jemandem eine fremde
    # Anmeldung unterschieben.
    response.set_cookie(
        OIDC_COOKIE,
        state,
        max_age=oidc.FLOW_SECONDS,
        httponly=True,
        secure=_cookie_secure(request, cfg),
        samesite="lax",
    )
    return response


@router.get("/oidc/callback")
def oidc_callback(
    request: Request,
    state: str = "",
    code: str = "",
    error: str = "",
    conn: sqlite3.Connection = Depends(get_db),
    cfg: Settings = Depends(settings),
) -> Response:
    ip = client_ip(request)
    flow = oidc.load_flow(conn, state) if state else None
    if flow is None or not cfg.oidc_enabled:
        return _login_error(request, oidc.EXPIRED)
    if flow["kind"] == "web" and not secrets.compare_digest(
        request.cookies.get(OIDC_COOKIE, ""), state
    ):
        return _login_error(request, oidc.EXPIRED)
    try:
        if error or not code:
            raise oidc.OidcError(oidc.FAILED)
        who = oidc.person(oidc.exchange(cfg, str(request.base_url), flow, code))
        with transaction(conn):
            user = oidc.user_for(conn, cfg, who)
            if flow["kind"] == "web":
                conn.execute("DELETE FROM oidc_flows WHERE id = ?", (flow["id"],))
                conn.execute("UPDATE users SET last_login_at = ? WHERE id = ?", (now(), user["id"]))
                log_login(conn, user["username"], user["id"], "web", ip, True, "SSO")
                response = _start_session(request, conn, cfg, user["id"], flow["next"])
                response.delete_cookie(OIDC_COOKIE)
                return response
            # Aus der App: erst hier im Browser bestätigen lassen, für welches Gerät.
            confirm = secrets.token_urlsafe(24)
            conn.execute(
                "UPDATE oidc_flows SET user_id = ?, confirm_hash = ? WHERE id = ?",
                (user["id"], token_hash(confirm), flow["id"]),
            )
    except oidc.OidcError as exc:
        conn.execute("DELETE FROM oidc_flows WHERE id = ?", (flow["id"],))
        log_login(conn, "", None, flow["kind"], ip, False, f"SSO: {exc}")
        return _login_error(request, str(exc))
    return render(
        request, "oidc_confirm.html", None, flow=flow, account=user, confirm=confirm, done=False
    )


@router.post("/oidc/confirm")
def oidc_confirm(
    request: Request,
    confirm: str = Form(""),
    action: str = Form(""),
    conn: sqlite3.Connection = Depends(get_db),
) -> Response:
    flow = conn.execute(
        "SELECT * FROM oidc_flows WHERE confirm_hash = ? AND kind = 'app' AND expires_at >= ?",
        (token_hash(confirm), now()),
    ).fetchone()
    if not confirm or flow is None:
        return _login_error(request, oidc.EXPIRED)
    if action != "allow":
        conn.execute("DELETE FROM oidc_flows WHERE id = ?", (flow["id"],))
        return render(request, "oidc_confirm.html", None, done=True, allowed=False)
    conn.execute("UPDATE oidc_flows SET confirmed = 1 WHERE id = ?", (flow["id"],))
    return render(request, "oidc_confirm.html", None, done=True, allowed=True)


@router.get("/logout", response_class=HTMLResponse)
def logout_page(
    request: Request,
    conn: sqlite3.Connection = Depends(get_db),
    cfg: Settings = Depends(settings),
) -> Response:
    """Zum Beispiel nach der Anmeldung beim Proxy, der zu /logout zurückleitet: noch
    angemeldet, dann Abmelden mit einem Klick anbieten, sonst zur Anmeldeseite."""
    user = resolve_token(
        conn,
        request.cookies.get(session_cookie(request, cfg), ""),
        "web",
        cfg.web_session_hours * 3600,
    )
    if user is None:
        return redirect("/login")
    return render(request, "logout.html", user)


@router.post("/logout")
def logout(
    request: Request,
    csrf: str = Form(""),
    user: sqlite3.Row = Depends(web_user),
    conn: sqlite3.Connection = Depends(get_db),
    cfg: Settings = Depends(settings),
) -> Response:
    check_csrf(user, csrf)
    name = session_cookie(request, cfg)
    revoke_token(conn, request.cookies.get(name, ""))
    response = redirect("/login")
    response.delete_cookie(name)
    return response


# --------------------------------------------------------------------------
# Geräte
# --------------------------------------------------------------------------


def _device_or_403(conn: sqlite3.Connection, user: sqlite3.Row, device_id: str) -> sqlite3.Row:
    row = conn.execute(
        "SELECT d.*, u.username AS owner FROM devices d LEFT JOIN users u ON u.id = d.user_id"
        " WHERE d.id = ?",
        (device_id,),
    ).fetchone()
    if row is None or (not user["is_admin"] and row["user_id"] != user["id"]):
        raise Forbidden
    return row


@router.get("/", response_class=HTMLResponse)
def devices(
    request: Request,
    user: sqlite3.Row = Depends(web_user),
    conn: sqlite3.Connection = Depends(get_db),
) -> HTMLResponse:
    sql = "SELECT d.*, u.username AS owner FROM devices d LEFT JOIN users u ON u.id = d.user_id"
    params: tuple = ()
    if not user["is_admin"]:
        sql += " WHERE d.user_id = ?"
        params = (user["id"],)
    rows = conn.execute(sql + " ORDER BY d.last_seen_at DESC NULLS LAST, d.id", params).fetchall()
    return render(request, "devices.html", user, devices=rows)


@router.get("/devices/{device_id}", response_class=HTMLResponse)
def device_detail(
    request: Request,
    device_id: str,
    user: sqlite3.Row = Depends(web_user),
    conn: sqlite3.Connection = Depends(get_db),
) -> HTMLResponse:
    device = _device_or_403(conn, user, device_id)
    connections = conn.execute(
        "SELECT * FROM connections WHERE device_id = ? ORDER BY started_at DESC, id DESC LIMIT 20",
        (device_id,),
    ).fetchall()
    users = conn.execute("SELECT id, username FROM users ORDER BY username").fetchall()
    try:
        sysinfo = json.dumps(json.loads(device["sysinfo"]), indent=2, ensure_ascii=False)
    except ValueError:
        sysinfo = device["sysinfo"]
    return render(
        request,
        "device.html",
        user,
        device=device,
        rows=connections,
        users=users,
        sysinfo=sysinfo,
    )


@router.post("/devices/{device_id}")
def device_update(
    request: Request,
    device_id: str,
    csrf: str = Form(""),
    note: str = Form(""),
    owner: str = Form(""),
    user: sqlite3.Row = Depends(web_user),
    conn: sqlite3.Connection = Depends(get_db),
) -> Response:
    check_csrf(user, csrf)
    device = _device_or_403(conn, user, device_id)
    owner_id = device["user_id"]
    if user["is_admin"]:
        owner_id = int(owner) if owner.isdigit() else None
    conn.execute(
        "UPDATE devices SET note = ?, user_id = ? WHERE id = ?",
        (note.strip()[:500], owner_id, device_id),
    )
    if owner_id != device["user_id"]:
        new_owner = conn.execute("SELECT username FROM users WHERE id = ?", (owner_id,)).fetchone()
        log_activity(
            conn,
            user,
            "device_owner",
            device_id,
            f"owner: {device['owner'] or '-'} -> {new_owner[0] if new_owner else '-'}",
            client_ip(request),
        )
    return redirect(f"/devices/{quote(device_id)}", "saved")


@router.post("/devices/{device_id}/delete")
def device_delete(
    request: Request,
    device_id: str,
    csrf: str = Form(""),
    user: sqlite3.Row = Depends(admin_user),
    conn: sqlite3.Connection = Depends(get_db),
) -> Response:
    check_csrf(user, csrf)
    conn.execute("DELETE FROM devices WHERE id = ?", (device_id,))
    log_activity(conn, user, "device_deleted", device_id, ip=client_ip(request))
    return redirect("/", "deleted")


# --------------------------------------------------------------------------
# Verlauf
# --------------------------------------------------------------------------


@router.get("/history", response_class=HTMLResponse)
def history(
    request: Request,
    device: str = "",
    page: int = 1,
    user: sqlite3.Row = Depends(web_user),
    conn: sqlite3.Connection = Depends(get_db),
) -> HTMLResponse:
    where, params = [], []
    if not user["is_admin"]:
        where.append("d.user_id = ?")
        params.append(user["id"])
    if device:
        where.append("c.device_id = ?")
        params.append(device)
    clause = (" WHERE " + " AND ".join(where)) if where else ""
    base = "FROM connections c LEFT JOIN devices d ON d.id = c.device_id" + clause
    total = conn.execute(f"SELECT COUNT(*) {base}", params).fetchone()[0]
    page = max(page, 1)
    rows = conn.execute(
        f"SELECT c.*, d.hostname {base} ORDER BY c.started_at DESC, c.id DESC LIMIT ? OFFSET ?",
        (*params, PAGE_SIZE, (page - 1) * PAGE_SIZE),
    ).fetchall()
    pages = max((total + PAGE_SIZE - 1) // PAGE_SIZE, 1)
    return render(
        request,
        "history.html",
        user,
        rows=rows,
        device=device,
        page=page,
        pages=pages,
        total=total,
        show_device=True,
    )


# --------------------------------------------------------------------------
# Adressbuch: dasselbe persönliche Adressbuch wie in der App
# --------------------------------------------------------------------------


def _color_hex(value: int) -> str:
    return f"#{value & 0xFFFFFF:06x}"


def _color_int(value: str) -> int:
    """#rrggbb aus dem Farbfeld als ARGB-Zahl, wie die App sie speichert."""
    value = value.strip().lstrip("#")
    if len(value) != 6 or any(c not in "0123456789abcdefABCDEF" for c in value):
        return 0xFF808080
    return 0xFF000000 | int(value, 16)


def _ab_page(
    request: Request,
    user: sqlite3.Row,
    conn: sqlite3.Connection,
    error: str | None = None,
    edit: dict[str, Any] | None = None,
) -> HTMLResponse:
    guid = personal_ab(conn, user["id"])
    tags = conn.execute(
        "SELECT name, color FROM ab_tags WHERE ab_guid = ? ORDER BY position", (guid,)
    ).fetchall()
    peers = [
        json.loads(r["data"])
        for r in conn.execute(
            "SELECT data FROM ab_peers WHERE ab_guid = ? ORDER BY position", (guid,)
        )
    ]
    colors = {t["name"]: _color_hex(t["color"]) for t in tags}
    return render(
        request,
        "address_book.html",
        user,
        status=400 if error else 200,
        peers=peers,
        tags=tags,
        colors=colors,
        edit=edit,
        error=error,
    )


@router.get("/address-book", response_class=HTMLResponse)
def address_book(
    request: Request,
    edit: str = "",
    user: sqlite3.Row = Depends(web_user),
    conn: sqlite3.Connection = Depends(get_db),
) -> HTMLResponse:
    peer = load_peer(conn, personal_ab(conn, user["id"]), edit) if edit else None
    return _ab_page(request, user, conn, edit=peer)


@router.post("/address-book/peers")
def address_book_save_peer(
    request: Request,
    csrf: str = Form(""),
    original: str = Form(""),
    peer_id: str = Form(""),
    alias: str = Form(""),
    note: str = Form(""),
    tags: list[str] = Form([]),
    user: sqlite3.Row = Depends(web_user),
    conn: sqlite3.Connection = Depends(get_db),
) -> Response:
    """Neuer Eintrag oder Änderung. Felder, die nur die App kennt (z. B. gespeicherte
    Passwörter), bleiben beim Ändern erhalten."""
    check_csrf(user, csrf)
    peer_id = "".join(peer_id.split())[:64]
    if not peer_id:
        return _ab_page(request, user, conn, _("Please enter the RustDesk ID."))
    with transaction(conn):
        guid = personal_ab(conn, user["id"])
        known = {
            r["name"] for r in conn.execute("SELECT name FROM ab_tags WHERE ab_guid = ?", (guid,))
        }
        peer = (load_peer(conn, guid, original) if original else None) or {}
        if peer_id != original and load_peer(conn, guid, peer_id) is not None:
            error = _("This ID is already in the address book.")
        else:
            error = None
            if original and original != peer_id:
                conn.execute(
                    "DELETE FROM ab_peers WHERE ab_guid = ? AND peer_id = ?", (guid, original)
                )
            peer.update(
                id=peer_id,
                alias=alias.strip()[:100],
                note=note.strip()[:500],
                tags=[t for t in dict.fromkeys(tags) if t in known],
            )
            save_peer(conn, guid, peer)
    if error:
        return _ab_page(request, user, conn, error)
    return redirect("/address-book", "saved")


@router.post("/address-book/peers/delete")
def address_book_delete_peer(
    csrf: str = Form(""),
    peer_id: str = Form(""),
    user: sqlite3.Row = Depends(web_user),
    conn: sqlite3.Connection = Depends(get_db),
) -> Response:
    check_csrf(user, csrf)
    guid = personal_ab(conn, user["id"])
    conn.execute("DELETE FROM ab_peers WHERE ab_guid = ? AND peer_id = ?", (guid, peer_id))
    return redirect("/address-book", "deleted")


@router.post("/address-book/tags")
def address_book_save_tag(
    request: Request,
    csrf: str = Form(""),
    original: str = Form(""),
    name: str = Form(""),
    color: str = Form(""),
    user: sqlite3.Row = Depends(web_user),
    conn: sqlite3.Connection = Depends(get_db),
) -> Response:
    """Neuer Tag oder Umbenennen/Umfärben; beim Umbenennen ändern sich alle Einträge mit."""
    check_csrf(user, csrf)
    name = name.strip()[:100]
    if not name:
        return _ab_page(request, user, conn, _("Please enter a name for the tag."))
    with transaction(conn):
        guid = personal_ab(conn, user["id"])
        exists = conn.execute(
            "SELECT 1 FROM ab_tags WHERE ab_guid = ? AND name = ?", (guid, name)
        ).fetchone()
        if exists and name != original:
            error = _("This tag already exists.")
        else:
            error = None
            if original and original != name:
                conn.execute(
                    "UPDATE ab_tags SET name = ? WHERE ab_guid = ? AND name = ?",
                    (name, guid, original),
                )
                rewrite_peer_tags(conn, guid, lambda ts: [name if t == original else t for t in ts])
            add_tag(conn, guid, name, _color_int(color))
    if error:
        return _ab_page(request, user, conn, error)
    return redirect("/address-book", "saved")


@router.post("/address-book/tags/delete")
def address_book_delete_tag(
    csrf: str = Form(""),
    name: str = Form(""),
    user: sqlite3.Row = Depends(web_user),
    conn: sqlite3.Connection = Depends(get_db),
) -> Response:
    check_csrf(user, csrf)
    with transaction(conn):
        guid = personal_ab(conn, user["id"])
        conn.execute("DELETE FROM ab_tags WHERE ab_guid = ? AND name = ?", (guid, name))
        rewrite_peer_tags(conn, guid, lambda ts: [t for t in ts if t != name])
    return redirect("/address-book", "deleted")


# --------------------------------------------------------------------------
# Konto
# --------------------------------------------------------------------------


def _account_page(
    request: Request, user: sqlite3.Row, conn: sqlite3.Connection, error: str | None = None
) -> HTMLResponse:
    sessions = conn.execute(
        "SELECT * FROM tokens WHERE user_id = ? ORDER BY last_used_at DESC", (user["id"],)
    ).fetchall()
    return render(
        request,
        "account.html",
        user,
        status=400 if error else 200,
        sessions=sessions,
        current_session=user["t_id"],
        recovery_left=unused_recovery_codes(conn, user["id"]),
        passkeys=passkeys.for_user(conn, user["id"]),
        error=error,
    )


@router.get("/account", response_class=HTMLResponse)
def account(
    request: Request,
    user: sqlite3.Row = Depends(web_user),
    conn: sqlite3.Connection = Depends(get_db),
) -> HTMLResponse:
    return _account_page(request, user, conn)


@router.post("/account/password")
def account_password(
    request: Request,
    csrf: str = Form(""),
    old: str = Form(""),
    new: str = Form(""),
    new2: str = Form(""),
    user: sqlite3.Row = Depends(web_user),
    conn: sqlite3.Connection = Depends(get_db),
) -> Response:
    check_csrf(user, csrf)
    if authenticate(conn, user["username"], old) is None:
        return _account_page(request, user, conn, _("The current password is wrong."))
    problem = password_problem(new)
    if problem:
        return _account_page(request, user, conn, _(problem))
    if new != new2:
        return _account_page(request, user, conn, _("The new passwords do not match."))
    with transaction(conn):
        conn.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?", (hash_password(new), user["id"])
        )
        # Alle anderen Sitzungen und App-Anmeldungen beenden.
        conn.execute("DELETE FROM tokens WHERE user_id = ? AND id != ?", (user["id"], user["t_id"]))
        log_activity(conn, user, "password_changed", user["username"], ip=client_ip(request))
    return redirect("/account", "password")


@router.post("/account/sessions/{token_id}/end")
def account_end_session(
    request: Request,
    token_id: int,
    csrf: str = Form(""),
    user: sqlite3.Row = Depends(web_user),
    conn: sqlite3.Connection = Depends(get_db),
    cfg: Settings = Depends(settings),
) -> Response:
    check_csrf(user, csrf)
    conn.execute("DELETE FROM tokens WHERE id = ? AND user_id = ?", (token_id, user["id"]))
    if token_id == user["t_id"]:
        response = redirect("/login")
        response.delete_cookie(session_cookie(request, cfg))
        return response
    return redirect("/account", "ended")


# Zwei-Faktor-Anmeldung: Einrichten, Wiederherstellungscodes, Abschalten


def _totp_setup_page(
    request: Request, user: sqlite3.Row, secret: str, error: str | None = None
) -> HTMLResponse:
    uri = provisioning_uri(secret, user["username"])
    return render(
        request,
        "totp_setup.html",
        user,
        status=400 if error else 200,
        qr=qr_svg(uri),
        secret=format_secret(secret),
        error=error,
    )


@router.post("/account/2fa/start")
def totp_start(
    request: Request,
    csrf: str = Form(""),
    user: sqlite3.Row = Depends(web_user),
    conn: sqlite3.Connection = Depends(get_db),
    cfg: Settings = Depends(settings),
) -> Response:
    check_csrf(user, csrf)
    if user["totp_enabled"]:
        return redirect("/account")
    secret = new_secret()
    conn.execute(
        "UPDATE users SET totp_secret = ? WHERE id = ?",
        (secretbox.seal(cfg.secret_key, secret), user["id"]),
    )
    return _totp_setup_page(request, user, secret)


@router.post("/account/2fa/confirm")
def totp_confirm(
    request: Request,
    csrf: str = Form(""),
    code: str = Form(""),
    user: sqlite3.Row = Depends(web_user),
    conn: sqlite3.Connection = Depends(get_db),
    cfg: Settings = Depends(settings),
) -> Response:
    check_csrf(user, csrf)
    secret = secret_of(user, cfg.secret_key)
    if user["totp_enabled"] or not secret:
        return redirect("/account")
    step = matching_step(secret, code)
    if step is None:
        return _totp_setup_page(request, user, secret, _("Wrong code. Please try again."))
    with transaction(conn):
        conn.execute(
            "UPDATE users SET totp_enabled = 1, totp_last_step = ? WHERE id = ?",
            (step, user["id"]),
        )
        codes = new_recovery_codes(conn, user["id"])
        log_activity(conn, user, "2fa_on", user["username"], ip=client_ip(request))
    return render(request, "recovery_codes.html", user, codes=codes, new=True)


def _password_and_code_ok(
    conn: sqlite3.Connection, user: sqlite3.Row, password: str, code: str, secret_key: str
) -> bool:
    if authenticate(conn, user["username"], password) is None:
        return False
    return verify_user_code(conn, user, code, secret_key) or use_recovery_code(
        conn, user["id"], code
    )


@router.post("/account/2fa/recovery")
def totp_recovery(
    request: Request,
    csrf: str = Form(""),
    password: str = Form(""),
    code: str = Form(""),
    user: sqlite3.Row = Depends(web_user),
    conn: sqlite3.Connection = Depends(get_db),
    cfg: Settings = Depends(settings),
) -> Response:
    check_csrf(user, csrf)
    if not user["totp_enabled"]:
        return redirect("/account")
    with transaction(conn):
        ok = _password_and_code_ok(conn, user, password, code, cfg.secret_key)
        codes = new_recovery_codes(conn, user["id"]) if ok else []
        if ok:
            log_activity(conn, user, "recovery_codes", user["username"], ip=client_ip(request))
    if not ok:
        return _account_page(request, user, conn, _("Wrong password or code."))
    return render(request, "recovery_codes.html", user, codes=codes, new=False)


@router.post("/account/2fa/disable")
def totp_disable(
    request: Request,
    csrf: str = Form(""),
    password: str = Form(""),
    code: str = Form(""),
    user: sqlite3.Row = Depends(web_user),
    conn: sqlite3.Connection = Depends(get_db),
    cfg: Settings = Depends(settings),
) -> Response:
    check_csrf(user, csrf)
    with transaction(conn):
        ok = _password_and_code_ok(conn, user, password, code, cfg.secret_key)
        if ok:
            disable_totp(conn, user["id"])
            log_activity(conn, user, "2fa_off", user["username"], ip=client_ip(request))
    if not ok:
        return _account_page(request, user, conn, _("Wrong password or code."))
    return redirect("/account", "2fa_off")


# --------------------------------------------------------------------------
# Benutzerverwaltung (nur Admins)
# --------------------------------------------------------------------------


def _users_page(
    request: Request, user: sqlite3.Row, conn: sqlite3.Connection, error: str | None = None
) -> HTMLResponse:
    users = conn.execute(
        "SELECT u.*, (SELECT COUNT(*) FROM devices d WHERE d.user_id = u.id) AS device_count"
        " FROM users u ORDER BY u.username"
    ).fetchall()
    return render(
        request, "users.html", user, status=400 if error else 200, users=users, error=error
    )


@router.get("/users", response_class=HTMLResponse)
def users_list(
    request: Request,
    user: sqlite3.Row = Depends(admin_user),
    conn: sqlite3.Connection = Depends(get_db),
) -> HTMLResponse:
    return _users_page(request, user, conn)


@router.post("/users/new")
def users_create(
    request: Request,
    csrf: str = Form(""),
    username: str = Form(""),
    display_name: str = Form(""),
    password: str = Form(""),
    is_admin: str = Form(""),
    user: sqlite3.Row = Depends(admin_user),
    conn: sqlite3.Connection = Depends(get_db),
) -> Response:
    check_csrf(user, csrf)
    username = username.strip()
    problem = username_problem(username) or password_problem(password)
    if problem:
        return _users_page(request, user, conn, _(problem))
    try:
        create_user(
            conn,
            username,
            password,
            is_admin=bool(is_admin),
            display_name=display_name.strip()[:100],
        )
    except sqlite3.IntegrityError:
        return _users_page(request, user, conn, _("This username already exists."))
    detail = "admin" if is_admin else ""
    log_activity(conn, user, "user_created", username, detail, client_ip(request))
    return redirect("/users", "created")


def _target_user(conn: sqlite3.Connection, user_id: int) -> sqlite3.Row:
    row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if row is None:
        raise Forbidden
    return row


def _user_page(
    request: Request,
    user: sqlite3.Row,
    conn: sqlite3.Connection,
    target: sqlite3.Row,
    error: str | None = None,
) -> HTMLResponse:
    devices = conn.execute(
        "SELECT * FROM devices WHERE user_id = ? ORDER BY id", (target["id"],)
    ).fetchall()
    return render(
        request,
        "user.html",
        user,
        status=400 if error else 200,
        target=target,
        devices=devices,
        passkey_count=passkeys.count(conn, target["id"]),
        error=error,
    )


@router.get("/users/{user_id}", response_class=HTMLResponse)
def users_detail(
    request: Request,
    user_id: int,
    user: sqlite3.Row = Depends(admin_user),
    conn: sqlite3.Connection = Depends(get_db),
) -> HTMLResponse:
    return _user_page(request, user, conn, _target_user(conn, user_id))


@router.post("/users/{user_id}")
def users_update(
    request: Request,
    user_id: int,
    csrf: str = Form(""),
    display_name: str = Form(""),
    email: str = Form(""),
    note: str = Form(""),
    is_admin: str = Form(""),
    enabled: str = Form(""),
    password: str = Form(""),
    user: sqlite3.Row = Depends(admin_user),
    conn: sqlite3.Connection = Depends(get_db),
) -> Response:
    check_csrf(user, csrf)
    target = _target_user(conn, user_id)
    if target["id"] == user["id"] and (not is_admin or not enabled):
        return _user_page(
            request, user, conn, target, _("You cannot disable or demote your own account.")
        )
    if password:
        problem = password_problem(password)
        if problem:
            return _user_page(request, user, conn, target, _(problem))
    with transaction(conn):
        conn.execute(
            "UPDATE users SET display_name = ?, email = ?, note = ?, is_admin = ?, enabled = ?"
            " WHERE id = ?",
            (
                display_name.strip()[:100],
                email.strip()[:200],
                note.strip()[:500],
                int(bool(is_admin)),
                int(bool(enabled)),
                user_id,
            ),
        )
        if password:
            conn.execute(
                "UPDATE users SET password_hash = ? WHERE id = ?",
                (hash_password(password), user_id),
            )
        if password or not enabled:
            # Neues Passwort oder gesperrt: bestehende Anmeldungen beenden.
            conn.execute(
                "DELETE FROM tokens WHERE user_id = ? AND id != ?", (user_id, user["t_id"])
            )
        changes = [
            text
            for text, changed in (
                ("password set", bool(password)),
                (
                    f"admin {'on' if is_admin else 'off'}",
                    bool(is_admin) != bool(target["is_admin"]),
                ),
                (
                    "enabled" if enabled else "disabled",
                    bool(enabled) != bool(target["enabled"]),
                ),
            )
            if changed
        ]
        log_activity(
            conn, user, "user_changed", target["username"], ", ".join(changes), client_ip(request)
        )
    return redirect(f"/users/{user_id}", "saved")


@router.post("/users/{user_id}/2fa/reset")
def users_reset_totp(
    request: Request,
    user_id: int,
    csrf: str = Form(""),
    user: sqlite3.Row = Depends(admin_user),
    conn: sqlite3.Connection = Depends(get_db),
) -> Response:
    """Falls jemand Telefon und Wiederherstellungscodes verloren hat."""
    check_csrf(user, csrf)
    target = _target_user(conn, user_id)
    with transaction(conn):
        reset_second_factors(conn, target["id"])
        log_activity(conn, user, "user_2fa_reset", target["username"], ip=client_ip(request))
    return redirect(f"/users/{user_id}", "2fa_off")


@router.post("/users/{user_id}/delete")
def users_delete(
    request: Request,
    user_id: int,
    csrf: str = Form(""),
    user: sqlite3.Row = Depends(admin_user),
    conn: sqlite3.Connection = Depends(get_db),
) -> Response:
    check_csrf(user, csrf)
    target = _target_user(conn, user_id)
    if target["id"] == user["id"]:
        return _user_page(request, user, conn, target, _("You cannot delete your own account."))
    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    log_activity(conn, user, "user_deleted", target["username"], ip=client_ip(request))
    return redirect("/users", "deleted")


ACTIVITY = {
    "password_changed": "Changed own password",
    "2fa_on": "Turned on two-factor sign-in",
    "2fa_off": "Turned off two-factor sign-in",
    "recovery_codes": "Created new recovery codes",
    "passkey_added": "Added a passkey",
    "passkey_removed": "Removed a passkey",
    "user_created": "Created a user",
    "user_created_sso": "Account created by single sign-on",
    "user_changed": "Changed a user",
    "user_deleted": "Deleted a user",
    "user_2fa_reset": "Turned off two-factor sign-in of a user",
    "device_owner": "Changed the owner of a device",
    "device_deleted": "Removed a device",
    "backup_created": "Created a backup",
    "backup_downloaded": "Downloaded a backup",
    "backup_uploaded": "Uploaded a backup",
    "backup_restored": "Restored a backup",
}


@router.get("/activity", response_class=HTMLResponse)
def activity_log(
    request: Request,
    user: sqlite3.Row = Depends(admin_user),
    conn: sqlite3.Connection = Depends(get_db),
) -> HTMLResponse:
    rows = conn.execute("SELECT * FROM activity ORDER BY id DESC LIMIT 300").fetchall()
    return render(request, "activity.html", user, rows=rows, labels=ACTIVITY)


@router.get("/logins", response_class=HTMLResponse)
def login_log(
    request: Request,
    user: sqlite3.Row = Depends(admin_user),
    conn: sqlite3.Connection = Depends(get_db),
) -> HTMLResponse:
    rows = conn.execute("SELECT * FROM login_events ORDER BY id DESC LIMIT 200").fetchall()
    return render(request, "logins.html", user, rows=rows)


# --------------------------------------------------------------------------
# Sicherungen (nur Admins)
# --------------------------------------------------------------------------

MAX_UPLOAD = 512 * 1024 * 1024


def _backups_page(
    request: Request, user: sqlite3.Row, cfg: Settings, error: str | None = None
) -> HTMLResponse:
    return render(
        request,
        "backups.html",
        user,
        status=400 if error else 200,
        backups=backup.list_backups(cfg.backups_path),
        folder=str(cfg.backups_path),
        keep=cfg.backup_keep,
        error=error,
    )


@router.get("/backups", response_class=HTMLResponse)
def backups_list(
    request: Request,
    user: sqlite3.Row = Depends(admin_user),
    cfg: Settings = Depends(settings),
) -> HTMLResponse:
    return _backups_page(request, user, cfg)


@router.post("/backups/new")
def backups_create(
    request: Request,
    csrf: str = Form(""),
    user: sqlite3.Row = Depends(admin_user),
    conn: sqlite3.Connection = Depends(get_db),
    cfg: Settings = Depends(settings),
) -> Response:
    check_csrf(user, csrf)
    made = backup.create_backup(cfg.db_path, cfg.backups_path, max(cfg.backup_keep, 1))
    log_activity(conn, user, "backup_created", made.name, ip=client_ip(request))
    return redirect("/backups", "backup")


@router.get("/backups/{name}")
def backups_download(
    request: Request,
    name: str,
    user: sqlite3.Row = Depends(admin_user),
    conn: sqlite3.Connection = Depends(get_db),
    cfg: Settings = Depends(settings),
) -> Response:
    path = backup.backup_file(cfg.backups_path, name)
    if path is None:
        raise Forbidden
    # Eine Sicherung enthält alle Konten: festhalten, wer sie geholt hat.
    log_activity(conn, user, "backup_downloaded", name, ip=client_ip(request))
    return FileResponse(path, filename=name, media_type="application/vnd.sqlite3")


@router.post("/backups/{name}/restore")
def backups_restore(
    request: Request,
    name: str,
    csrf: str = Form(""),
    user: sqlite3.Row = Depends(admin_user),
    cfg: Settings = Depends(settings),
) -> Response:
    check_csrf(user, csrf)
    path = backup.backup_file(cfg.backups_path, name)
    if path is None:
        raise Forbidden
    problem = backup.check_backup(path)
    if problem:
        return _backups_page(request, user, cfg, _(problem))
    # Erst die gewählte Sicherung beiseitelegen, dann den jetzigen Stand sichern (das
    # könnte die älteste Sicherung löschen), dann zurückspielen.
    chosen = cfg.backups_path / "restore.tmp"
    shutil.copyfile(path, chosen)
    try:
        backup.create_backup(cfg.db_path, cfg.backups_path, max(cfg.backup_keep, 1) + 1)
        backup.restore_backup(cfg.db_path, chosen)
    finally:
        chosen.unlink(missing_ok=True)
    # Nach dem Zurückspielen in die nun aktive Datenbank schreiben.
    conn = connect(cfg.db_path)
    try:
        log_activity(conn, user, "backup_restored", name, ip=client_ip(request))
    finally:
        conn.close()
    return redirect("/backups", "restored")


@router.post("/backups/upload")
async def backups_upload(
    request: Request,
    csrf: str = Form(""),
    file: UploadFile = File(...),
    user: sqlite3.Row = Depends(admin_user),
    cfg: Settings = Depends(settings),
) -> Response:
    check_csrf(user, csrf)
    folder = cfg.backups_path
    folder.mkdir(parents=True, exist_ok=True)
    tmp = folder / "upload.tmp"
    size = 0
    try:
        with tmp.open("wb") as out:
            while chunk := await file.read(1024 * 1024):
                size += len(chunk)
                if size > MAX_UPLOAD:
                    return _backups_page(request, user, cfg, _("The file is too large."))
                out.write(chunk)
        problem = backup.check_backup(tmp)
        if problem:
            return _backups_page(request, user, cfg, _(problem))
        name = backup.free_name(folder)
        tmp.replace(folder / name)
    finally:
        tmp.unlink(missing_ok=True)
    conn = connect(cfg.db_path)
    try:
        log_activity(conn, user, "backup_uploaded", name, ip=client_ip(request))
    finally:
        conn.close()
    return redirect("/backups", "uploaded")


# --------------------------------------------------------------------------
# Passkeys und Sicherheitsschlüssel (WebAuthn). Der Browser spricht hier JSON
# (static/passkeys.js); Fehler kommen als {"error": "..."} in der Sprache der Seite.
# --------------------------------------------------------------------------


def _any_passkeys(db_path: str) -> bool:
    """Den Knopf „Mit Passkey anmelden“ nur zeigen, wenn es überhaupt Passkeys gibt."""
    conn = connect(db_path)
    try:
        return passkeys.any_registered(conn)
    finally:
        conn.close()


def _rp(request: Request, cfg: Settings) -> tuple[str, str]:
    return passkeys.relying_party(cfg.public_url, str(request.base_url))


def _json_error(message: str, status: int = 400) -> JSONResponse:
    return JSONResponse({"error": _(message)}, status_code=status)


async def _json_body(request: Request) -> dict[str, Any]:
    try:
        data = await request.json()
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


def _credential(data: dict[str, Any]) -> dict[str, Any]:
    value = data.get("credential")
    return value if isinstance(value, dict) else {}


@router.post("/login/passkey/options")
def passkey_login_options(
    request: Request,
    conn: sqlite3.Connection = Depends(get_db),
    cfg: Settings = Depends(settings),
    lim: LoginLimiter = Depends(limiter),
    starts: RateLimiter = Depends(public_limiter),
) -> Response:
    ip = client_ip(request)
    if lim.blocked(ip, "") or not starts.allow(f"start:{ip}"):
        return _json_error("Too many failed logins. Please try again later.", 429)
    rp_id, _origin = _rp(request, cfg)
    return JSONResponse(passkeys.authentication_options(conn, rp_id))


@router.post("/login/passkey")
async def passkey_login(
    request: Request,
    conn: sqlite3.Connection = Depends(get_db),
    cfg: Settings = Depends(settings),
    lim: LoginLimiter = Depends(limiter),
) -> Response:
    """Anmeldung ohne Passwort: Der Passkey prüft selbst PIN oder Fingerabdruck und ist
    damit schon zwei Faktoren."""
    data = await _json_body(request)
    ip = client_ip(request)
    rp_id, origin = _rp(request, cfg)
    try:
        with transaction(conn):
            user_id = passkeys.authenticate(
                conn, str(data.get("token", "")), _credential(data), rp_id, origin
            )
            user = conn.execute(
                "SELECT * FROM users WHERE id = ? AND enabled = 1", (user_id,)
            ).fetchone()
            if user is None:
                raise passkeys.PasskeyError(oidc.DISABLED)
            conn.execute("UPDATE users SET last_login_at = ? WHERE id = ?", (now(), user_id))
            log_login(conn, user["username"], user_id, "web", ip, True, "passkey")
            return _start_session(
                request, conn, cfg, user_id, safe_next(str(data.get("next", "/")))
            )
    except passkeys.PasskeyError as exc:
        lim.failure(ip, "")
        log_login(conn, "", None, "web", ip, False, f"passkey: {exc}")
        return _json_error(str(exc))


@router.post("/login/code/passkey/options")
async def passkey_second_options(
    request: Request,
    conn: sqlite3.Connection = Depends(get_db),
    cfg: Settings = Depends(settings),
) -> Response:
    data = await _json_body(request)
    with transaction(conn):
        user = resolve_pending_login(conn, str(data.get("pending", "")), "web")
        if user is None:
            return _json_error(passkeys.EXPIRED)
        rp_id, _origin = _rp(request, cfg)
        return JSONResponse(passkeys.authentication_options(conn, rp_id, user["id"]))


@router.post("/login/code/passkey")
async def passkey_second(
    request: Request,
    conn: sqlite3.Connection = Depends(get_db),
    cfg: Settings = Depends(settings),
    lim: LoginLimiter = Depends(limiter),
) -> Response:
    data = await _json_body(request)
    ip = client_ip(request)
    rp_id, origin = _rp(request, cfg)
    try:
        with transaction(conn):
            user = resolve_pending_login(conn, str(data.get("pending", "")), "web")
            if user is None:
                raise passkeys.PasskeyError(passkeys.EXPIRED)
            passkeys.authenticate(
                conn, str(data.get("token", "")), _credential(data), rp_id, origin, user["id"]
            )
            finish_pending_login(conn, user["p_id"])
            conn.execute("UPDATE users SET last_login_at = ? WHERE id = ?", (now(), user["id"]))
            log_login(conn, user["username"], user["id"], "web", ip, True, "2FA passkey")
            return _start_session(
                request, conn, cfg, user["id"], safe_next(str(data.get("next", "/")))
            )
    except passkeys.PasskeyError as exc:
        lim.failure(ip, "")
        return _json_error(str(exc))


@router.post("/account/passkeys/options")
async def passkey_register_options(
    request: Request,
    user: sqlite3.Row = Depends(web_user),
    conn: sqlite3.Connection = Depends(get_db),
    cfg: Settings = Depends(settings),
) -> Response:
    data = await _json_body(request)
    check_csrf(user, str(data.get("csrf", "")))
    rp_id, _origin = _rp(request, cfg)
    try:
        return JSONResponse(passkeys.registration_options(conn, user, rp_id))
    except passkeys.PasskeyError as exc:
        return _json_error(str(exc))


@router.post("/account/passkeys")
async def passkey_register(
    request: Request,
    user: sqlite3.Row = Depends(web_user),
    conn: sqlite3.Connection = Depends(get_db),
    cfg: Settings = Depends(settings),
) -> Response:
    data = await _json_body(request)
    check_csrf(user, str(data.get("csrf", "")))
    rp_id, origin = _rp(request, cfg)
    try:
        with transaction(conn):
            passkeys.register(
                conn,
                user,
                str(data.get("token", "")),
                _credential(data),
                str(data.get("name", "")),
                rp_id,
                origin,
            )
            log_activity(
                conn,
                user,
                "passkey_added",
                user["username"],
                str(data.get("name", ""))[:60],
                client_ip(request),
            )
            # Erster zweiter Faktor: Wiederherstellungscodes, falls der Passkey verloren geht.
            codes = (
                []
                if unused_recovery_codes(conn, user["id"])
                else new_recovery_codes(conn, user["id"])
            )
    except passkeys.PasskeyError as exc:
        return _json_error(str(exc))
    if codes:
        return render(request, "recovery_codes.html", user, codes=codes, new=False, passkey=True)
    return redirect("/account", "passkey")


@router.post("/account/passkeys/{passkey_id}/delete")
def passkey_delete(
    request: Request,
    passkey_id: int,
    csrf: str = Form(""),
    user: sqlite3.Row = Depends(web_user),
    conn: sqlite3.Connection = Depends(get_db),
) -> Response:
    check_csrf(user, csrf)
    with transaction(conn):
        removed = conn.execute(
            "DELETE FROM passkeys WHERE id = ? AND user_id = ? RETURNING name",
            (passkey_id, user["id"]),
        ).fetchone()
        if removed:
            log_activity(
                conn, user, "passkey_removed", user["username"], removed[0], client_ip(request)
            )
        if not user["totp_enabled"] and not has_passkeys(conn, user["id"]):
            # Kein zweiter Faktor mehr: die Wiederherstellungscodes haben keinen Zweck.
            conn.execute("DELETE FROM recovery_codes WHERE user_id = ?", (user["id"],))
    return redirect("/account", "deleted")
