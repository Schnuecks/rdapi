"""Tägliche Sicherung der Datenbank und Wiederherstellung.

Die Sicherung nutzt die Backup-Funktion von SQLite und ist damit auch im laufenden
Betrieb in sich stimmig. Dateien heißen rdapi-YYYYMMDD-HHMMSS.sqlite3.
"""

from __future__ import annotations

import re
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path

from .db import MIGRATIONS, connect, init_db

NAME = re.compile(r"^rdapi-(\d{8}-\d{6})\.sqlite3$")
# So oft prüft der Dienst, ob die tägliche Sicherung fällig ist.
CHECK_INTERVAL = 3600
DAY = 86400

DAMAGED = "The backup is damaged."
NOT_A_BACKUP = "This is not an RDAPI backup."
TOO_NEW = "The backup is from a newer version of RDAPI."
# Für die Übersetzung: diese Texte zeigt die Weboberfläche an.
MESSAGES = (DAMAGED, NOT_A_BACKUP, TOO_NEW)


@dataclass(frozen=True)
class Backup:
    name: str
    size: int
    created_at: int


def list_backups(folder: Path) -> list[Backup]:
    if not folder.is_dir():
        return []
    found = []
    for path in folder.iterdir():
        if NAME.match(path.name) and path.is_file():
            stat = path.stat()
            found.append(Backup(path.name, stat.st_size, int(stat.st_mtime)))
    return sorted(found, key=lambda b: b.name, reverse=True)


def backup_file(folder: Path, name: str) -> Path | None:
    """Pfad einer vorhandenen Sicherung; nur gültige Namen, kein Weg aus dem Ordner."""
    if not NAME.match(name):
        return None
    path = folder / name
    return path if path.is_file() else None


def free_name(folder: Path) -> str:
    """Neuer Dateiname nach der Uhrzeit; bei zwei Sicherungen in derselben Sekunde
    bekommt die zweite die nächste Sekunde, damit nichts überschrieben wird."""
    ts = int(time.time())
    while True:
        name = time.strftime("rdapi-%Y%m%d-%H%M%S.sqlite3", time.gmtime(ts))
        if not (folder / name).exists():
            return name
        ts += 1


def create_backup(db_path: str, folder: Path, keep: int) -> Backup:
    folder.mkdir(parents=True, exist_ok=True)
    name = free_name(folder)
    target = folder / name
    tmp = folder / (name + ".tmp")
    src = connect(db_path)
    try:
        dst = sqlite3.connect(tmp)
        try:
            src.backup(dst)
        finally:
            dst.close()
    finally:
        src.close()
    tmp.replace(target)
    prune_backups(folder, keep)
    stat = target.stat()
    return Backup(name, stat.st_size, int(stat.st_mtime))


def prune_backups(folder: Path, keep: int) -> None:
    for old in list_backups(folder)[max(keep, 1) :]:
        (folder / old.name).unlink(missing_ok=True)


def backup_due(folder: Path) -> bool:
    latest = list_backups(folder)
    return not latest or latest[0].created_at < time.time() - DAY


def check_backup(path: Path) -> str | None:
    """Fehlermeldung, wenn die Datei keine brauchbare Sicherung ist, sonst None."""
    try:
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        try:
            if conn.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                return DAMAGED
            version = conn.execute("PRAGMA user_version").fetchone()[0]
            tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master")}
        finally:
            conn.close()
    except sqlite3.DatabaseError:
        return NOT_A_BACKUP
    if "users" not in tables or version < 1:
        return NOT_A_BACKUP
    if version > len(MIGRATIONS):
        return TOO_NEW
    return None


def restore_backup(db_path: str, path: Path) -> None:
    """Spielt die Sicherung in die laufende Datenbank ein und hebt sie danach auf den
    aktuellen Stand. Vorher check_backup aufrufen."""
    src = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        dst = connect(db_path)
        try:
            src.backup(dst)
        finally:
            dst.close()
    finally:
        src.close()
    init_db(db_path)
