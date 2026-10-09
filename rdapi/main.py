"""Einstiegspunkt: uvicorn --factory rdapi.main:create_app"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
import logging
from collections.abc import AsyncIterator
from dataclasses import replace
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException

from . import api, backup, i18n, secretbox, web
from .config import Settings
from .db import connect, init_db, prune, transaction
from .security import (
    LoginLimiter,
    RateLimiter,
    clear_setup_code,
    create_user,
    has_users,
    password_problem,
    setup_code,
    username_problem,
)

log = logging.getLogger("rdapi")

PRUNE_INTERVAL = 6 * 3600

# Inline erlaubt ist nur das kleine Skript im Kopf von base.html (Hash) und style-Attribute
# für Tag-Farben; alles andere kommt von hier selbst. Formulare dürfen auch auf HTTPS-Adressen
# weiterleiten: Hinter einem Reverse Proxy mit Anmeldeseite (z. B. Authelia) leitet der Proxy
# ein Formular zur Anmeldeseite um, wenn dessen Sitzung abgelaufen ist. Mit nur 'self'
# blockiert der Browser das ganze Absenden still (z. B. „Abmelden passiert nichts“).
CSP = (
    "default-src 'self'; "
    "script-src 'self' 'sha256-{script_hash}'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; "
    "frame-ancestors 'none'; base-uri 'none'; form-action 'self' https:; object-src 'none'"
)
INLINE_SCRIPT = 'document.documentElement.classList.add("js")'
SECURITY_HEADERS = {
    "Content-Security-Policy": CSP.format(
        script_hash=base64.b64encode(hashlib.sha256(INLINE_SCRIPT.encode()).digest()).decode()
    ),
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}


HSTS = "max-age=31536000"
# Größte Anfrage in Bytes; nur das Hochladen einer Sicherung darf größer sein.
MAX_REQUEST = 2 * 1024 * 1024
MAX_UPLOAD_REQUEST = 513 * 1024 * 1024


class BodyLimit:
    """Lehnt zu große Anfragen ab, bevor sie gelesen werden; schützt vor Anfragen, die den
    Arbeitsspeicher füllen sollen."""

    def __init__(self, app) -> None:
        self.app = app

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        limit = MAX_UPLOAD_REQUEST if scope["path"] == "/backups/upload" else MAX_REQUEST
        for name, value in scope.get("headers", []):
            if name == b"content-length" and value.isdigit() and int(value) > limit:
                await send(
                    {
                        "type": "http.response.start",
                        "status": 413,
                        "headers": [(b"content-type", b"text/plain")],
                    }
                )
                await send({"type": "http.response.body", "body": b"Request too large."})
                return None
        seen = 0

        async def limited():
            nonlocal seen
            message = await receive()
            if message["type"] == "http.request":
                seen += len(message.get("body", b""))
                if seen > limit:
                    # Ohne Längenangabe gesendet und zu groß: wie ein Abbruch behandeln.
                    return {"type": "http.disconnect"}
            return message

        return await self.app(scope, limited, send)


def checked_oidc(cfg: Settings) -> Settings:
    """Anmeldung über einen Anbieter nur über HTTPS (außer auf diesem Rechner); sonst
    ließe sich die Anmeldung unterwegs fälschen."""
    if not cfg.oidc_issuer:
        return cfg
    parts = urlsplit(cfg.oidc_issuer)
    local = parts.hostname in {"localhost", "127.0.0.1", "::1"}
    if parts.scheme == "https" or (parts.scheme == "http" and local):
        return cfg
    log.error(
        "RDAPI_OIDC_ISSUER must start with https:// - single sign-on is turned off: %s",
        cfg.oidc_issuer,
    )
    return replace(cfg, oidc_issuer="")


def encrypt_secrets(cfg: Settings) -> None:
    conn = connect(cfg.db_path)
    try:
        with transaction(conn):
            secretbox.migrate(conn, cfg.secret_key)
    finally:
        conn.close()


def bootstrap_admin(cfg: Settings) -> None:
    """Legt beim ersten Start einen Admin an, wenn noch kein Benutzer existiert."""
    if not cfg.bootstrap_admin_user:
        return
    conn = connect(cfg.db_path)
    try:
        with transaction(conn):
            if conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]:
                return
            problem = username_problem(cfg.bootstrap_admin_user) or password_problem(
                cfg.bootstrap_admin_password
            )
            if problem:
                raise SystemExit(f"Cannot create the first admin: {problem}")
            create_user(conn, cfg.bootstrap_admin_user, cfg.bootstrap_admin_password, is_admin=True)
            clear_setup_code(conn)
            log.warning("Admin %s created.", cfg.bootstrap_admin_user)
    finally:
        conn.close()


def announce_setup(cfg: Settings) -> None:
    """Beim Start ohne Konto: Einrichtungscode ins Log schreiben."""
    conn = connect(cfg.db_path)
    try:
        if has_users(conn):
            return
        code = setup_code(conn)
    finally:
        conn.close()
    # Zweisprachig: diese Zeile muss jeder finden, egal in welcher Sprache die Doku gelesen wird
    log.warning(
        "No user account yet: open RDAPI in the browser and create the admin account. "
        "Setup code: %s",
        code,
    )
    log.warning(
        "Noch kein Benutzerkonto: Öffne RDAPI im Browser und lege das Admin-Konto an. "
        "Einrichtungscode: %s",
        code,
    )


async def _prune_loop(cfg: Settings) -> None:
    while True:
        try:
            conn = connect(cfg.db_path)
            try:
                prune(conn, cfg.history_days, cfg.unowned_device_days)
            finally:
                conn.close()
        except Exception:  # noqa: BLE001 - Aufräumen darf den Dienst nie beenden
            log.exception("Cleanup failed")
        await asyncio.sleep(PRUNE_INTERVAL)


async def _backup_loop(cfg: Settings) -> None:
    while True:
        try:
            if backup.backup_due(cfg.backups_path):
                made = await asyncio.to_thread(
                    backup.create_backup, cfg.db_path, cfg.backups_path, cfg.backup_keep
                )
                log.info("Backup created: %s", made.name)
        except Exception:  # noqa: BLE001 - eine fehlgeschlagene Sicherung beendet nichts
            log.exception("Backup failed")
        await asyncio.sleep(backup.CHECK_INTERVAL)


def create_app(cfg: Settings | None = None) -> FastAPI:
    cfg = checked_oidc(cfg or Settings.from_env())
    init_db(cfg.db_path)
    encrypt_secrets(cfg)
    bootstrap_admin(cfg)
    announce_setup(cfg)
    web.setup_filters(cfg.timezone)

    @contextlib.asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        tasks = [asyncio.create_task(_prune_loop(cfg))]
        if cfg.backup_keep > 0:
            tasks.append(asyncio.create_task(_backup_loop(cfg)))
        yield
        for task in tasks:
            task.cancel()

    app = FastAPI(
        title="RDAPI",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    app.state.settings = cfg
    app.state.limiter = LoginLimiter(
        cfg.login_max_failures_ip, cfg.login_max_failures_user, cfg.login_window_seconds
    )
    app.state.device_limiter = RateLimiter(cfg.new_devices_per_hour, 3600)
    # Anfragen ohne Anmeldung, die etwas anlegen (Anmeldung mit Passkey oder beim Anbieter
    # beginnen), und Gerätemeldungen; je Adresse.
    app.state.public_limiter = RateLimiter(30, 600)
    app.state.report_limiter = RateLimiter(cfg.device_requests_per_minute, 60)
    app.add_exception_handler(api.ApiError, api.api_error_response)
    app.add_exception_handler(web.LoginRequired, web.login_redirect_handler)
    app.add_exception_handler(web.Forbidden, web.forbidden_handler)

    @app.exception_handler(StarletteHTTPException)
    async def http_error(request: Request, exc: StarletteHTTPException):
        # Nach der Anmeldung beim Proxy kehrt der Browser mit GET zu einer Adresse zurück, die
        # nur Formulare (POST) annimmt. Statt „Method Not Allowed“ zurück zur Startseite.
        if (
            exc.status_code == 405
            and request.method == "GET"
            and not request.url.path.startswith("/api/")
        ):
            return RedirectResponse("/", status_code=303)
        return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)

    @app.middleware("http")
    async def language(request: Request, call_next):
        i18n.set_language(
            i18n.pick_language(
                request.cookies.get(i18n.LANG_COOKIE), request.headers.get("accept-language")
            )
        )
        response = await call_next(request)
        for name, value in SECURITY_HEADERS.items():
            response.headers.setdefault(name, value)
        if response.headers.get("content-type", "").startswith(("text/html", "application/json")):
            # Seiten und Antworten mit persönlichen Daten nicht zwischenspeichern.
            response.headers.setdefault("Cache-Control", "no-store")
        if request.url.scheme == "https":
            response.headers.setdefault("Strict-Transport-Security", HSTS)
        return response

    app.include_router(api.router)
    app.include_router(web.router)
    app.mount("/static", StaticFiles(directory=Path(__file__).parent / "static"), name="static")
    app.add_middleware(BodyLimit)
    return app
