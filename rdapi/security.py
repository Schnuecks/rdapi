"""Passwörter, Tokens und Begrenzung fehlgeschlagener Anmeldungen."""

from __future__ import annotations

import contextlib
import hashlib
import secrets
import sqlite3
import threading
import time
from collections import defaultdict, deque

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from .db import now

_hasher = PasswordHasher()
# Wird bei unbekannten Benutzern geprüft, damit die Antwortzeit nicht verrät,
# ob es den Namen gibt.
_DUMMY_HASH = _hasher.hash(secrets.token_urlsafe(16))

MIN_PASSWORD_LENGTH = 10
USERNAME_MAX = 64


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def password_problem(password: str) -> str | None:
    if len(password) < MIN_PASSWORD_LENGTH:
        return "The password must be at least 10 characters long."
    if len(password) > 1024:
        return "The password is too long."
    return None


def username_problem(username: str) -> str | None:
    if not username:
        return "Please enter a username."
    if len(username) > USERNAME_MAX:
        return "The username is too long."
    if not all(c.isalnum() or c in "._-@" for c in username):
        return "The username may only contain letters, digits and . _ - @"
    return None


def authenticate(conn: sqlite3.Connection, username: str, password: str) -> sqlite3.Row | None:
    """Liefert den aktiven Benutzer bei korrektem Passwort, sonst None."""
    row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    if row is None:
        with contextlib.suppress(VerificationError):
            _hasher.verify(_DUMMY_HASH, password)
        return None
    try:
        _hasher.verify(row["password_hash"], password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return None
    if _hasher.check_needs_rehash(row["password_hash"]):
        conn.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?", (hash_password(password), row["id"])
        )
    if not row["enabled"]:
        return None
    return row


def create_user(
    conn: sqlite3.Connection,
    username: str,
    password: str,
    *,
    is_admin: bool = False,
    display_name: str = "",
    email: str = "",
) -> int:
    cur = conn.execute(
        "INSERT INTO users (username, password_hash, display_name, email, is_admin, created_at)"
        " VALUES (?, ?, ?, ?, ?, ?)",
        (username, hash_password(password), display_name, email, int(is_admin), now()),
    )
    return int(cur.lastrowid)


SETUP_KEY = "setup_code"
# Ohne leicht verwechselbare Zeichen (0/O, 1/I), damit er sich aus dem Log abtippen lässt
_SETUP_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"


def has_users(conn: sqlite3.Connection) -> bool:
    return conn.execute("SELECT 1 FROM users LIMIT 1").fetchone() is not None


def setup_code(conn: sqlite3.Connection) -> str:
    """Einrichtungscode, solange es kein Konto gibt. Liegt in der Datenbank, damit
    Container-Log, Kommandozeile und Weboberfläche denselben Code kennen."""
    row = conn.execute("SELECT value FROM settings WHERE key = ?", (SETUP_KEY,)).fetchone()
    if row:
        return row["value"]
    code = "-".join("".join(secrets.choice(_SETUP_ALPHABET) for _ in range(4)) for _ in range(3))
    conn.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", (SETUP_KEY, code))
    return conn.execute("SELECT value FROM settings WHERE key = ?", (SETUP_KEY,)).fetchone()[0]


def setup_code_valid(conn: sqlite3.Connection, code: str) -> bool:
    wanted = setup_code(conn).replace("-", "")
    given = "".join(code.upper().split()).replace("-", "")
    return secrets.compare_digest(given.encode(), wanted.encode())


def clear_setup_code(conn: sqlite3.Connection) -> None:
    conn.execute("DELETE FROM settings WHERE key = ?", (SETUP_KEY,))


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def issue_token(
    conn: sqlite3.Connection,
    user_id: int,
    kind: str,
    lifetime_seconds: int,
    *,
    device_id: str = "",
    device_uuid: str = "",
    client_info: str = "",
    ip: str = "",
) -> tuple[str, str]:
    """Legt einen Token an und gibt (Token, CSRF-Token) zurück."""
    token = secrets.token_urlsafe(32)
    csrf = secrets.token_urlsafe(24) if kind == "web" else ""
    ts = now()
    conn.execute(
        "INSERT INTO tokens (token_hash, user_id, kind, device_id, device_uuid, client_info, ip,"
        " csrf, created_at, last_used_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            token_hash(token),
            user_id,
            kind,
            device_id,
            device_uuid,
            client_info,
            ip,
            csrf,
            ts,
            ts,
            ts + lifetime_seconds,
        ),
    )
    return token, csrf


def resolve_token(
    conn: sqlite3.Connection, token: str, kind: str, lifetime_seconds: int
) -> sqlite3.Row | None:
    """Prüft einen Token und verlängert ihn gleitend.

    Liefert eine Zeile mit den Spalten des Tokens (Präfix t_) und des Benutzers.
    """
    if not token:
        return None
    row = conn.execute(
        "SELECT u.*, t.id AS t_id, t.csrf AS t_csrf, t.last_used_at AS t_last_used_at,"
        " t.expires_at AS t_expires_at"
        " FROM tokens t JOIN users u ON u.id = t.user_id"
        " WHERE t.token_hash = ? AND t.kind = ?",
        (token_hash(token), kind),
    ).fetchone()
    ts = now()
    if row is None or row["t_expires_at"] < ts or not row["enabled"]:
        return None
    # Schreibzugriffe begrenzen: höchstens einmal pro Minute verlängern.
    if ts - row["t_last_used_at"] >= 60:
        conn.execute(
            "UPDATE tokens SET last_used_at = ?, expires_at = ? WHERE id = ?",
            (ts, ts + lifetime_seconds, row["t_id"]),
        )
    return row


def revoke_token(conn: sqlite3.Connection, token: str) -> None:
    conn.execute("DELETE FROM tokens WHERE token_hash = ?", (token_hash(token),))


class LoginLimiter:
    """Zählt fehlgeschlagene Anmeldungen je IP und je Benutzername im Speicher.

    Ergänzt das Rate-Limit und die IP-Sperrliste im Reverse Proxy; nach einem Neustart ist der
    Zähler leer, was bewusst in Kauf genommen wird.
    """

    def __init__(self, max_ip: int, max_user: int, window: int) -> None:
        self.max_ip = max_ip
        self.max_user = max_user
        self.window = window
        self._lock = threading.Lock()
        self._fails: dict[str, deque[float]] = defaultdict(deque)
        self._block_logged: dict[str, float] = {}

    def _count(self, key: str, ts: float) -> int:
        q = self._fails.get(key)
        if not q:
            return 0
        while q and q[0] < ts - self.window:
            q.popleft()
        if not q:
            del self._fails[key]
            return 0
        return len(q)

    def blocked(self, ip: str, username: str, *, known_ip: bool = False) -> bool:
        """known_ip: Von dieser Adresse hat sich der Benutzer schon erfolgreich angemeldet.
        Dann gilt nur die Grenze je Adresse, damit niemand von außen den Benutzer
        aussperren kann, indem er absichtlich falsche Passwörter schickt."""
        ts = time.monotonic()
        with self._lock:
            if self._count(f"ip:{ip}", ts) >= self.max_ip:
                return True
            return not known_ip and self._count(f"user:{username.lower()}", ts) >= self.max_user

    def failure(self, ip: str, username: str) -> None:
        ts = time.monotonic()
        with self._lock:
            self._fails[f"ip:{ip}"].append(ts)
            self._fails[f"user:{username.lower()}"].append(ts)

    def success(self, ip: str, username: str) -> None:
        with self._lock:
            self._fails.pop(f"user:{username.lower()}", None)

    def log_block(self, ip: str) -> bool:
        """Ob ein gesperrter Versuch dieser Adresse protokolliert werden soll: höchstens
        einmal je Minute, damit niemand mit Versuchen das Protokoll füllt."""
        ts = time.monotonic()
        with self._lock:
            last = self._block_logged.get(ip)
            # monotonic() beginnt beim Systemstart bei null; deshalb „noch nie“ als None.
            if last is not None and ts - last < 60:
                return False
            self._block_logged[ip] = ts
            if len(self._block_logged) > 10000:
                self._block_logged.clear()
            return True


def log_login(
    conn: sqlite3.Connection,
    username: str,
    user_id: int | None,
    source: str,
    ip: str,
    success: bool,
    detail: str = "",
) -> None:
    conn.execute(
        "INSERT INTO login_events (username, user_id, source, ip, success, detail, created_at)"
        " VALUES (?, ?, ?, ?, ?, ?, ?)",
        (username[:USERNAME_MAX], user_id, source, ip, int(success), detail[:200], now()),
    )


def known_login_ip(conn: sqlite3.Connection, username: str, ip: str) -> bool:
    """Ob sich dieser Benutzer von dieser Adresse schon einmal erfolgreich angemeldet hat."""
    if not username or not ip:
        return False
    return (
        conn.execute(
            "SELECT 1 FROM login_events WHERE success = 1 AND ip = ?"
            " AND username = ? COLLATE NOCASE LIMIT 1",
            (ip, username),
        ).fetchone()
        is not None
    )


def log_activity(
    conn: sqlite3.Connection,
    actor: sqlite3.Row | None,
    action: str,
    target: str = "",
    detail: str = "",
    ip: str = "",
) -> None:
    """Hält eine sicherheitsrelevante Aktion fest (Seite „Aktivität“ für Admins)."""
    conn.execute(
        "INSERT INTO activity (actor_id, actor, action, target, detail, ip, created_at)"
        " VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            actor["id"] if actor is not None else None,
            actor["username"] if actor is not None else "",
            action,
            target[:100],
            detail[:200],
            ip,
            now(),
        ),
    )


class RateLimiter:
    """Höchstens `limit` Ereignisse je Schlüssel im Zeitfenster (im Speicher)."""

    def __init__(self, limit: int, window: int) -> None:
        self.limit = limit
        self.window = window
        self._lock = threading.Lock()
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def allow(self, key: str) -> bool:
        if self.limit <= 0:
            return True
        ts = time.monotonic()
        with self._lock:
            q = self._hits[key]
            while q and q[0] < ts - self.window:
                q.popleft()
            if len(q) >= self.limit:
                return False
            q.append(ts)
            return True


# --------------------------------------------------------------------------
# Zwei-Faktor-Anmeldung: Zwischenschritt und Wiederherstellungscodes
# --------------------------------------------------------------------------

PENDING_SECONDS = 300
PENDING_MAX_ATTEMPTS = 5
RECOVERY_CODES = 8


def start_pending_login(conn: sqlite3.Connection, user_id: int, source: str) -> str:
    """Passwort war richtig, es fehlt der zweite Faktor. Liefert ein kurzlebiges Geheimnis,
    das beim zweiten Schritt mitgeschickt wird."""
    secret = secrets.token_urlsafe(32)
    conn.execute(
        "INSERT INTO pending_logins (token_hash, user_id, source, expires_at) VALUES (?, ?, ?, ?)",
        (token_hash(secret), user_id, source, now() + PENDING_SECONDS),
    )
    return secret


def resolve_pending_login(conn: sqlite3.Connection, secret: str, source: str) -> sqlite3.Row | None:
    """Benutzer zum Zwischenschritt; zählt den Versuch mit. Nach zu vielen Versuchen oder
    nach Ablauf ist der Zwischenschritt ungültig."""
    if not secret:
        return None
    row = conn.execute(
        "SELECT p.id AS p_id, p.attempts AS p_attempts, p.expires_at AS p_expires_at, u.*"
        " FROM pending_logins p JOIN users u ON u.id = p.user_id"
        " WHERE p.token_hash = ? AND p.source = ?",
        (token_hash(secret), source),
    ).fetchone()
    if row is None:
        return None
    if row["p_expires_at"] < now() or row["p_attempts"] >= PENDING_MAX_ATTEMPTS:
        conn.execute("DELETE FROM pending_logins WHERE id = ?", (row["p_id"],))
        return None
    conn.execute("UPDATE pending_logins SET attempts = attempts + 1 WHERE id = ?", (row["p_id"],))
    if not row["enabled"]:
        return None
    return row


def finish_pending_login(conn: sqlite3.Connection, pending_id: int) -> None:
    conn.execute("DELETE FROM pending_logins WHERE id = ?", (pending_id,))


def _normalize_recovery(code: str) -> str:
    return "".join(code.upper().split()).replace("-", "")


def new_recovery_codes(conn: sqlite3.Connection, user_id: int) -> list[str]:
    """Ersetzt alle Wiederherstellungscodes und liefert die neuen im Klartext (nur einmal)."""
    conn.execute("DELETE FROM recovery_codes WHERE user_id = ?", (user_id,))
    codes = []
    for _ in range(RECOVERY_CODES):
        code = "-".join(
            "".join(secrets.choice(_SETUP_ALPHABET) for _ in range(4)) for _ in range(2)
        )
        codes.append(code)
        conn.execute(
            "INSERT INTO recovery_codes (user_id, code_hash) VALUES (?, ?)",
            (user_id, token_hash(_normalize_recovery(code))),
        )
    return codes


def use_recovery_code(conn: sqlite3.Connection, user_id: int, code: str) -> bool:
    cur = conn.execute(
        "UPDATE recovery_codes SET used_at = ? WHERE user_id = ? AND code_hash = ?"
        " AND used_at IS NULL",
        (now(), user_id, token_hash(_normalize_recovery(code))),
    )
    return cur.rowcount == 1


def unused_recovery_codes(conn: sqlite3.Connection, user_id: int) -> int:
    return conn.execute(
        "SELECT COUNT(*) FROM recovery_codes WHERE user_id = ? AND used_at IS NULL", (user_id,)
    ).fetchone()[0]


def has_passkeys(conn: sqlite3.Connection, user_id: int) -> bool:
    return (
        conn.execute("SELECT 1 FROM passkeys WHERE user_id = ? LIMIT 1", (user_id,)).fetchone()
        is not None
    )


def second_factor_required(conn: sqlite3.Connection, user: sqlite3.Row) -> bool:
    """In der Weboberfläche: Code aus der App oder ein Passkey nach dem Passwort.
    (Die RustDesk-App kennt nur den Code; dort zählt allein totp_enabled.)"""
    return bool(user["totp_enabled"]) or has_passkeys(conn, user["id"])


def disable_totp(conn: sqlite3.Connection, user_id: int) -> None:
    conn.execute(
        "UPDATE users SET totp_secret = '', totp_enabled = 0, totp_last_step = 0 WHERE id = ?",
        (user_id,),
    )
    # Wiederherstellungscodes bleiben, solange noch Passkeys als zweiter Faktor da sind.
    if not has_passkeys(conn, user_id):
        conn.execute("DELETE FROM recovery_codes WHERE user_id = ?", (user_id,))
        conn.execute("DELETE FROM pending_logins WHERE user_id = ?", (user_id,))


def reset_second_factors(conn: sqlite3.Connection, user_id: int) -> None:
    """Für Admins: Code, Passkeys und Wiederherstellungscodes entfernen."""
    conn.execute("DELETE FROM passkeys WHERE user_id = ?", (user_id,))
    disable_totp(conn, user_id)
