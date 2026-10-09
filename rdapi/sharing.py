"""Gruppen und geteilte Adressbücher: wer was sehen und ändern darf."""

from __future__ import annotations

import sqlite3
import uuid
from dataclasses import dataclass

from .db import now

# Rechte wie in der RustDesk-App (ShareRule).
READ, READ_WRITE, FULL = 1, 2, 3
RULES = {
    READ: "Read only",
    READ_WRITE: "Read and change",
    FULL: "Full control",
}


@dataclass(frozen=True)
class Book:
    guid: str
    name: str  # leer beim persönlichen Adressbuch
    note: str
    owner: str
    rule: int

    @property
    def personal(self) -> bool:
        return not self.name

    @property
    def writable(self) -> bool:
        return self.rule >= READ_WRITE


# --------------------------------------------------------------------------
# Gruppen
# --------------------------------------------------------------------------


def group_ids(conn: sqlite3.Connection, user_id: int) -> list[int]:
    return [
        r[0]
        for r in conn.execute("SELECT group_id FROM group_members WHERE user_id = ?", (user_id,))
    ]


def accessible_user_ids(conn: sqlite3.Connection, user: sqlite3.Row) -> list[int]:
    """Benutzer, deren Geräte jemand in der App sieht: Admins alle, sonst man selbst
    und die Mitglieder der eigenen Gruppen (nur aktive Konten)."""
    if user["is_admin"]:
        sql, params = "SELECT id FROM users WHERE enabled = 1", ()
    else:
        sql = (
            "SELECT id FROM users WHERE enabled = 1 AND (id = ? OR id IN ("
            " SELECT m.user_id FROM group_members m JOIN group_members mine"
            " ON mine.group_id = m.group_id WHERE mine.user_id = ?))"
        )
        params = (user["id"], user["id"])
    return [r[0] for r in conn.execute(sql + " ORDER BY id", params)]


def set_members(conn: sqlite3.Connection, group_id: int, user_ids: list[int]) -> None:
    conn.execute("DELETE FROM group_members WHERE group_id = ?", (group_id,))
    conn.executemany(
        "INSERT OR IGNORE INTO group_members (group_id, user_id)"
        " SELECT ?, id FROM users WHERE id = ?",
        [(group_id, uid) for uid in dict.fromkeys(user_ids)],
    )


# --------------------------------------------------------------------------
# Adressbücher
# --------------------------------------------------------------------------


def personal_ab(conn: sqlite3.Connection, user_id: int) -> str:
    row = conn.execute("SELECT guid FROM address_books WHERE user_id = ?", (user_id,)).fetchone()
    if row:
        return row["guid"]
    conn.execute(
        "INSERT OR IGNORE INTO address_books (guid, user_id, created_at) VALUES (?, ?, ?)",
        (str(uuid.uuid4()), user_id, now()),
    )
    return conn.execute("SELECT guid FROM address_books WHERE user_id = ?", (user_id,)).fetchone()[
        "guid"
    ]


def create_shared(conn: sqlite3.Connection, name: str, note: str, creator_id: int) -> str:
    guid = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO address_books (guid, name, note, created_by, created_at)"
        " VALUES (?, ?, ?, ?, ?)",
        (guid, name, note, creator_id, now()),
    )
    return guid


def _shared_rows(conn: sqlite3.Connection, user: sqlite3.Row) -> list[tuple[sqlite3.Row, int]]:
    rows = conn.execute(
        "SELECT b.*, COALESCE(u.username, '') AS owner FROM address_books b"
        " LEFT JOIN users u ON u.id = b.created_by WHERE b.user_id IS NULL"
        " ORDER BY b.name COLLATE NOCASE, b.guid"
    ).fetchall()
    if user["is_admin"]:
        return [(r, FULL) for r in rows]
    rules: dict[str, int] = {}
    for r in conn.execute(
        "SELECT ab_guid, MAX(rule) AS rule FROM ab_rules WHERE user_id = ?"
        " OR group_id IN (SELECT group_id FROM group_members WHERE user_id = ?)"
        " GROUP BY ab_guid",
        (user["id"], user["id"]),
    ):
        rules[r["ab_guid"]] = r["rule"]
    return [(r, rules[r["guid"]]) for r in rows if r["guid"] in rules]


def shared_books(conn: sqlite3.Connection, user: sqlite3.Row) -> list[Book]:
    """Geteilte Adressbücher, die der Benutzer sieht, mit seinem Recht darauf.
    Admins sehen alle mit voller Kontrolle."""
    return [
        Book(r["guid"], r["name"], r["note"], r["owner"], rule)
        for r, rule in _shared_rows(conn, user)
    ]


def books(conn: sqlite3.Connection, user: sqlite3.Row) -> list[Book]:
    """Persönliches Adressbuch zuerst, dann die geteilten."""
    own = Book(personal_ab(conn, user["id"]), "", "", user["username"], FULL)
    return [own, *shared_books(conn, user)]


def book_for(conn: sqlite3.Connection, user: sqlite3.Row, guid: str) -> Book | None:
    """Das Adressbuch, wenn der Benutzer es sehen darf, sonst None."""
    if not guid:
        return None
    return next((b for b in books(conn, user) if b.guid == guid), None)


def rules_of(conn: sqlite3.Connection, guid: str) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT r.*, u.username, g.name AS group_name FROM ab_rules r"
        " LEFT JOIN users u ON u.id = r.user_id LEFT JOIN user_groups g ON g.id = r.group_id"
        " WHERE r.ab_guid = ? ORDER BY r.group_id IS NULL, g.name, u.username",
        (guid,),
    ).fetchall()


def set_rule(
    conn: sqlite3.Connection, guid: str, rule: int, user_id: int | None, group_id: int | None
) -> None:
    column = "user_id" if user_id is not None else "group_id"
    target = user_id if user_id is not None else group_id
    conn.execute(f"DELETE FROM ab_rules WHERE ab_guid = ? AND {column} = ?", (guid, target))
    conn.execute(
        "INSERT INTO ab_rules (ab_guid, user_id, group_id, rule) VALUES (?, ?, ?, ?)",
        (guid, user_id, group_id, rule),
    )
