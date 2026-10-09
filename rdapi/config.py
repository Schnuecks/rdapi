"""Konfiguration aus Umgebungsvariablen (Präfix RDAPI_)."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def _env(name: str, default: str = "") -> str:
    return os.environ.get(f"RDAPI_{name}", default).strip()


def _env_int(name: str, default: int) -> int:
    raw = _env(name)
    return int(raw) if raw else default


def _read_secret(name: str) -> str:
    """Liest RDAPI_<name>_FILE (Docker-Secret) oder ersatzweise RDAPI_<name>."""
    path = _env(f"{name}_FILE")
    if path:
        return Path(path).read_text(encoding="utf-8").strip()
    return _env(name)


def _cookie_secure() -> bool | None:
    raw = _env("COOKIE_SECURE").lower()
    if raw in ("", "auto"):
        return None
    return raw in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    db_path: str
    timezone: str
    # Lebensdauer eines App-Tokens; jede Nutzung verlängert ihn wieder.
    app_token_days: int
    # Lebensdauer einer Sitzung in der Weboberfläche (Stunden, gleitend).
    web_session_hours: int
    # None = automatisch: Secure-Cookie, wenn die Anfrage über HTTPS kam
    cookie_secure: bool | None
    history_days: int
    # Ab wann ein Gerät als offline gilt (Sekunden seit letztem Heartbeat).
    online_seconds: int
    login_max_failures_ip: int
    login_max_failures_user: int
    login_window_seconds: int
    bootstrap_admin_user: str
    bootstrap_admin_password: str
    # Geräte ohne Besitzer werden nach so vielen Tagen ohne Meldung gelöscht (0 = nie).
    unowned_device_days: int = 30
    # Neue Geräte je Adresse und Stunde; schützt vor erfundenen Geräten in Massen.
    new_devices_per_hour: int = 20
    # Tägliche Sicherung der Datenbank; backup_keep = 0 schaltet sie ab.
    backup_dir: str = ""
    backup_keep: int = 7
    # Anmeldung über einen OpenID-Connect-Anbieter; ohne Aussteller abgeschaltet.
    oidc_issuer: str = ""
    oidc_client_id: str = ""
    oidc_client_secret: str = ""
    oidc_name: str = "SSO"
    oidc_admin_group: str = ""
    oidc_create_users: bool = True
    # Öffentliche Adresse, falls sie sich nicht aus der Anfrage ergibt (Rücksprung-URL).
    public_url: str = ""
    # Schlüssel zum Verschlüsseln der TOTP-Geheimnisse in der Datenbank (optional).
    secret_key: str = ""
    # Anfragen je Adresse und Minute an die Gerätemeldungen (Heartbeat, Sysinfo, Verlauf).
    device_requests_per_minute: int = 600

    @property
    def oidc_enabled(self) -> bool:
        return bool(self.oidc_issuer and self.oidc_client_id)

    @classmethod
    def from_env(cls) -> Settings:
        return cls(
            db_path=_env("DB_PATH", "/data/rdapi.sqlite3"),
            timezone=_env("TZ") or os.environ.get("TZ", "") or "Europe/Berlin",
            app_token_days=_env_int("APP_TOKEN_DAYS", 90),
            web_session_hours=_env_int("WEB_SESSION_HOURS", 12),
            cookie_secure=_cookie_secure(),
            history_days=_env_int("HISTORY_DAYS", 365),
            online_seconds=_env_int("ONLINE_SECONDS", 60),
            login_max_failures_ip=_env_int("LOGIN_MAX_FAILURES_IP", 10),
            login_max_failures_user=_env_int("LOGIN_MAX_FAILURES_USER", 20),
            login_window_seconds=_env_int("LOGIN_WINDOW_SECONDS", 900),
            bootstrap_admin_user=_env("ADMIN_USER"),
            bootstrap_admin_password=_read_secret("ADMIN_PASSWORD"),
            unowned_device_days=_env_int("UNOWNED_DEVICE_DAYS", 30),
            new_devices_per_hour=_env_int("NEW_DEVICES_PER_HOUR", 20),
            backup_dir=_env("BACKUP_DIR"),
            backup_keep=_env_int("BACKUP_KEEP", 7),
            oidc_issuer=_env("OIDC_ISSUER").rstrip("/"),
            oidc_client_id=_env("OIDC_CLIENT_ID"),
            oidc_client_secret=_read_secret("OIDC_CLIENT_SECRET"),
            oidc_name=_env("OIDC_NAME") or "SSO",
            oidc_admin_group=_env("OIDC_ADMIN_GROUP"),
            oidc_create_users=_env("OIDC_CREATE_USERS", "true").lower()
            not in {"0", "false", "no", "off"},
            public_url=_env("PUBLIC_URL").rstrip("/"),
            secret_key=_read_secret("SECRET_KEY"),
            device_requests_per_minute=_env_int("DEVICE_REQUESTS_PER_MINUTE", 600),
        )

    @property
    def backups_path(self) -> Path:
        if self.backup_dir:
            return Path(self.backup_dir)
        return Path(self.db_path).resolve().parent / "backups"
