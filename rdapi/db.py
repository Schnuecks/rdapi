"""SQLite-Zugriff und Schema."""

from __future__ import annotations

import sqlite3
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

# Jede Migration hebt PRAGMA user_version um eins an. Neue Änderungen nur
# hinten anhängen, bestehende Einträge nie verändern.
MIGRATIONS: list[str] = [
    """
    CREATE TABLE users (
        id             INTEGER PRIMARY KEY,
        username       TEXT    NOT NULL UNIQUE COLLATE NOCASE,
        password_hash  TEXT    NOT NULL,
        display_name   TEXT    NOT NULL DEFAULT '',
        email          TEXT    NOT NULL DEFAULT '',
        note           TEXT    NOT NULL DEFAULT '',
        is_admin       INTEGER NOT NULL DEFAULT 0,
        enabled        INTEGER NOT NULL DEFAULT 1,
        created_at     INTEGER NOT NULL,
        last_login_at  INTEGER
    );

    -- App-Tokens (kind='app') und Sitzungen der Weboberfläche (kind='web').
    -- Gespeichert wird nur der SHA-256 des Tokens.
    CREATE TABLE tokens (
        id            INTEGER PRIMARY KEY,
        token_hash    TEXT    NOT NULL UNIQUE,
        user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        kind          TEXT    NOT NULL CHECK (kind IN ('app', 'web')),
        device_id     TEXT    NOT NULL DEFAULT '',
        device_uuid   TEXT    NOT NULL DEFAULT '',
        client_info   TEXT    NOT NULL DEFAULT '',
        ip            TEXT    NOT NULL DEFAULT '',
        csrf          TEXT    NOT NULL DEFAULT '',
        created_at    INTEGER NOT NULL,
        last_used_at  INTEGER NOT NULL,
        expires_at    INTEGER NOT NULL
    );
    CREATE INDEX tokens_user ON tokens(user_id);

    -- Geräte, die sich per Sysinfo/Heartbeat melden. id = RustDesk-ID.
    CREATE TABLE devices (
        id            TEXT    PRIMARY KEY,
        uuid          TEXT    NOT NULL DEFAULT '',
        user_id       INTEGER REFERENCES users(id) ON DELETE SET NULL,
        hostname      TEXT    NOT NULL DEFAULT '',
        username      TEXT    NOT NULL DEFAULT '',
        os            TEXT    NOT NULL DEFAULT '',
        cpu           TEXT    NOT NULL DEFAULT '',
        memory        TEXT    NOT NULL DEFAULT '',
        version       TEXT    NOT NULL DEFAULT '',
        note          TEXT    NOT NULL DEFAULT '',
        sysinfo       TEXT    NOT NULL DEFAULT '{}',
        created_at    INTEGER NOT NULL,
        last_seen_at  INTEGER,
        last_ip       TEXT    NOT NULL DEFAULT ''
    );
    CREATE INDEX devices_user ON devices(user_id);

    -- Ein persönliches Adressbuch je Benutzer.
    CREATE TABLE address_books (
        guid        TEXT    PRIMARY KEY,
        user_id     INTEGER NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
        created_at  INTEGER NOT NULL
    );

    -- Einträge speichern das JSON des Clients unverändert, damit neue Felder
    -- der App ohne Schemaänderung erhalten bleiben.
    CREATE TABLE ab_peers (
        ab_guid     TEXT    NOT NULL REFERENCES address_books(guid) ON DELETE CASCADE,
        peer_id     TEXT    NOT NULL,
        data        TEXT    NOT NULL,
        position    INTEGER NOT NULL,
        updated_at  INTEGER NOT NULL,
        PRIMARY KEY (ab_guid, peer_id)
    );

    CREATE TABLE ab_tags (
        ab_guid   TEXT    NOT NULL REFERENCES address_books(guid) ON DELETE CASCADE,
        name      TEXT    NOT NULL,
        color     INTEGER NOT NULL DEFAULT 0,
        position  INTEGER NOT NULL,
        PRIMARY KEY (ab_guid, name)
    );

    -- Verbindungsverlauf: eine Zeile je eingehender Verbindung auf einem Gerät.
    CREATE TABLE connections (
        id            INTEGER PRIMARY KEY,
        device_id     TEXT    NOT NULL,
        conn_id       INTEGER NOT NULL,
        session_id    TEXT    NOT NULL DEFAULT '',
        ip            TEXT    NOT NULL DEFAULT '',
        peer_id       TEXT    NOT NULL DEFAULT '',
        peer_name     TEXT    NOT NULL DEFAULT '',
        conn_type     INTEGER,
        primary_auth  INTEGER,
        started_at    INTEGER NOT NULL,
        authed_at     INTEGER,
        ended_at      INTEGER
    );
    CREATE INDEX connections_device ON connections(device_id, conn_id);
    CREATE INDEX connections_started ON connections(started_at);

    -- Datei- und Alarm-Audits, roh gespeichert.
    CREATE TABLE audit_events (
        id          INTEGER PRIMARY KEY,
        kind        TEXT    NOT NULL,
        device_id   TEXT    NOT NULL DEFAULT '',
        payload     TEXT    NOT NULL,
        created_at  INTEGER NOT NULL
    );
    CREATE INDEX audit_events_created ON audit_events(created_at);

    -- Der Client wiederholt Audit-Posts und schickt dazu eine Nonce mit.
    CREATE TABLE seen_nonces (
        nonce       TEXT    PRIMARY KEY,
        created_at  INTEGER NOT NULL
    );

    CREATE TABLE login_events (
        id          INTEGER PRIMARY KEY,
        username    TEXT    NOT NULL,
        user_id     INTEGER REFERENCES users(id) ON DELETE SET NULL,
        source      TEXT    NOT NULL,
        ip          TEXT    NOT NULL DEFAULT '',
        success     INTEGER NOT NULL,
        detail      TEXT    NOT NULL DEFAULT '',
        created_at  INTEGER NOT NULL
    );
    CREATE INDEX login_events_created ON login_events(created_at);
    """,
    """
    -- Kleine Schlüssel-Wert-Ablage, z. B. der Einrichtungscode vor dem ersten Konto.
    CREATE TABLE settings (
        key    TEXT PRIMARY KEY,
        value  TEXT NOT NULL
    );
    """,
    """
    -- Zwei-Faktor-Anmeldung (TOTP). totp_last_step verhindert, dass derselbe Code
    -- zweimal angenommen wird.
    ALTER TABLE users ADD COLUMN totp_secret TEXT NOT NULL DEFAULT '';
    ALTER TABLE users ADD COLUMN totp_enabled INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE users ADD COLUMN totp_last_step INTEGER NOT NULL DEFAULT 0;

    -- Wiederherstellungscodes, falls das Telefon fehlt; nur als SHA-256 gespeichert.
    CREATE TABLE recovery_codes (
        id         INTEGER PRIMARY KEY,
        user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        code_hash  TEXT    NOT NULL,
        used_at    INTEGER
    );
    CREATE INDEX recovery_codes_user ON recovery_codes(user_id);

    -- Anmeldung nach richtigem Passwort, die noch auf den zweiten Faktor wartet.
    CREATE TABLE pending_logins (
        id          INTEGER PRIMARY KEY,
        token_hash  TEXT    NOT NULL UNIQUE,
        user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        source      TEXT    NOT NULL CHECK (source IN ('app', 'web')),
        attempts    INTEGER NOT NULL DEFAULT 0,
        expires_at  INTEGER NOT NULL
    );
    """,
    """
    -- Anmeldung über einen OpenID-Connect-Anbieter: oidc_sub verknüpft das Konto dauerhaft.
    ALTER TABLE users ADD COLUMN oidc_sub TEXT NOT NULL DEFAULT '';
    CREATE UNIQUE INDEX users_oidc_sub ON users(oidc_sub) WHERE oidc_sub != '';

    -- Laufende Anmeldungen beim Anbieter, aus der Weboberfläche oder der App.
    CREATE TABLE oidc_flows (
        id             INTEGER PRIMARY KEY,
        state_hash     TEXT    NOT NULL UNIQUE,
        kind           TEXT    NOT NULL CHECK (kind IN ('web', 'app')),
        nonce          TEXT    NOT NULL,
        verifier       TEXT    NOT NULL,
        next           TEXT    NOT NULL DEFAULT '/',
        app_code_hash  TEXT    NOT NULL DEFAULT '',
        device_id      TEXT    NOT NULL DEFAULT '',
        device_uuid    TEXT    NOT NULL DEFAULT '',
        client_info    TEXT    NOT NULL DEFAULT '',
        user_id        INTEGER REFERENCES users(id) ON DELETE CASCADE,
        confirm_hash   TEXT    NOT NULL DEFAULT '',
        confirmed      INTEGER NOT NULL DEFAULT 0,
        expires_at     INTEGER NOT NULL
    );
    CREATE INDEX oidc_flows_app_code ON oidc_flows(app_code_hash);
    """,
    """
    -- Passkeys und Sicherheitsschlüssel (WebAuthn) für die Weboberfläche.
    CREATE TABLE passkeys (
        id             INTEGER PRIMARY KEY,
        user_id        INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        credential_id  TEXT    NOT NULL UNIQUE,  -- base64url
        public_key     BLOB    NOT NULL,
        sign_count     INTEGER NOT NULL DEFAULT 0,
        name           TEXT    NOT NULL DEFAULT '',
        created_at     INTEGER NOT NULL,
        last_used_at   INTEGER
    );
    CREATE INDEX passkeys_user ON passkeys(user_id);

    -- Offene Anfragen an den Browser (Registrieren oder Anmelden), kurz gültig.
    CREATE TABLE webauthn_challenges (
        id          INTEGER PRIMARY KEY,
        token_hash  TEXT    NOT NULL UNIQUE,
        challenge   BLOB    NOT NULL,
        purpose     TEXT    NOT NULL CHECK (purpose IN ('register', 'login', 'second')),
        user_id     INTEGER REFERENCES users(id) ON DELETE CASCADE,
        expires_at  INTEGER NOT NULL
    );
    """,
    """
    -- Protokoll sicherheitsrelevanter Aktionen: Admins ändern Benutzer, Geräte oder
    -- Sicherungen, Benutzer ändern ihre eigene Anmeldung.
    CREATE TABLE activity (
        id          INTEGER PRIMARY KEY,
        actor_id    INTEGER REFERENCES users(id) ON DELETE SET NULL,
        actor       TEXT    NOT NULL,
        action      TEXT    NOT NULL,
        target      TEXT    NOT NULL DEFAULT '',
        detail      TEXT    NOT NULL DEFAULT '',
        ip          TEXT    NOT NULL DEFAULT '',
        created_at  INTEGER NOT NULL
    );
    CREATE INDEX activity_created ON activity(created_at);
    """,
]


def now() -> int:
    return int(time.time())


def connect(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path, timeout=10, isolation_level=None, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 10000")
    return conn


def init_db(path: str) -> None:
    if path != ":memory:":
        Path(path).parent.mkdir(parents=True, exist_ok=True)
    conn = connect(path)
    try:
        conn.execute("PRAGMA journal_mode = WAL")
        version = conn.execute("PRAGMA user_version").fetchone()[0]
        for index, script in enumerate(MIGRATIONS[version:], start=version + 1):
            conn.executescript(f"BEGIN;\n{script}\nPRAGMA user_version = {index};\nCOMMIT;")
    finally:
        conn.close()


@contextmanager
def transaction(conn: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    conn.execute("COMMIT")


def prune(conn: sqlite3.Connection, history_days: int, unowned_device_days: int) -> None:
    """Entfernt abgelaufene Tokens, alte Nonces, alten Verlauf und verwaiste Geräte."""
    ts = now()
    cutoff = ts - history_days * 86400
    conn.execute("DELETE FROM tokens WHERE expires_at < ?", (ts,))
    conn.execute("DELETE FROM pending_logins WHERE expires_at < ?", (ts,))
    conn.execute("DELETE FROM oidc_flows WHERE expires_at < ?", (ts,))
    conn.execute("DELETE FROM webauthn_challenges WHERE expires_at < ?", (ts,))
    if unowned_device_days > 0:
        # Geräte ohne Besitzer, die sich lange nicht gemeldet haben. Meldet sich eins
        # wieder, wird es neu angelegt.
        conn.execute(
            "DELETE FROM devices WHERE user_id IS NULL AND COALESCE(last_seen_at, created_at) < ?",
            (ts - unowned_device_days * 86400,),
        )
    conn.execute("DELETE FROM seen_nonces WHERE created_at < ?", (ts - 86400,))
    conn.execute("DELETE FROM connections WHERE started_at < ?", (cutoff,))
    conn.execute("DELETE FROM audit_events WHERE created_at < ?", (cutoff,))
    conn.execute("DELETE FROM login_events WHERE created_at < ?", (cutoff,))
    conn.execute("DELETE FROM activity WHERE created_at < ?", (cutoff,))
