"""Command line administration, e.g. inside the container:

docker compose exec rdapi python -m rdapi.cli create-user alice --admin
docker compose exec rdapi python -m rdapi.cli set-password alice
docker compose exec rdapi python -m rdapi.cli list-users
docker compose exec rdapi python -m rdapi.cli setup-code
docker compose exec rdapi python -m rdapi.cli reset-2fa alice
"""

from __future__ import annotations

import argparse
import getpass
import sqlite3
import sys

from .config import Settings
from .db import connect, init_db, transaction
from .security import (
    clear_setup_code,
    create_user,
    has_users,
    hash_password,
    password_problem,
    reset_second_factors,
    setup_code,
    username_problem,
)


def _ask_password() -> str:
    first = getpass.getpass("New password: ")
    if getpass.getpass("Repeat: ") != first:
        sys.exit("The passwords do not match.")
    problem = password_problem(first)
    if problem:
        sys.exit(problem)
    return first


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="rdapi")
    sub = parser.add_subparsers(dest="cmd", required=True)
    create = sub.add_parser("create-user", help="create a user")
    create.add_argument("username")
    create.add_argument("--admin", action="store_true", help="give the user admin rights")
    reset = sub.add_parser("set-password", help="set a password and end all sessions")
    reset.add_argument("username")
    sub.add_parser("list-users", help="list all users")
    tfa = sub.add_parser(
        "reset-2fa", help="turn off two-factor sign-in and remove passkeys of a user"
    )
    tfa.add_argument("username")
    sub.add_parser(
        "setup-code", help="show the setup code for creating the first admin in the web UI"
    )
    args = parser.parse_args(argv)

    cfg = Settings.from_env()
    init_db(cfg.db_path)
    conn = connect(cfg.db_path)
    try:
        if args.cmd == "setup-code":
            if has_users(conn):
                sys.exit("Setup is already done: a user account exists.")
            print(setup_code(conn))
        elif args.cmd == "list-users":
            for row in conn.execute(
                "SELECT username, is_admin, enabled, totp_enabled FROM users ORDER BY 1"
            ):
                flags = ", ".join(
                    f
                    for f, on in (("admin", row[1]), ("disabled", not row[2]), ("2FA", row[3]))
                    if on
                )
                print(row[0] + (f" ({flags})" if flags else ""))
        elif args.cmd == "create-user":
            problem = username_problem(args.username)
            if problem:
                sys.exit(problem)
            password = _ask_password()
            try:
                create_user(conn, args.username, password, is_admin=args.admin)
                clear_setup_code(conn)
            except sqlite3.IntegrityError:
                sys.exit("This username already exists.")
            print(f"User {args.username} created.")
        elif args.cmd == "reset-2fa":
            row = conn.execute(
                "SELECT id FROM users WHERE username = ?", (args.username,)
            ).fetchone()
            if row is None:
                sys.exit("User not found.")
            with transaction(conn):
                reset_second_factors(conn, row[0])
            print("Two-factor sign-in turned off, passkeys removed.")
        elif args.cmd == "set-password":
            row = conn.execute(
                "SELECT id FROM users WHERE username = ?", (args.username,)
            ).fetchone()
            if row is None:
                sys.exit("User not found.")
            password = _ask_password()
            with transaction(conn):
                conn.execute(
                    "UPDATE users SET password_hash = ? WHERE id = ?",
                    (hash_password(password), row[0]),
                )
                conn.execute("DELETE FROM tokens WHERE user_id = ?", (row[0],))
            print("Password set, all sessions ended.")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
