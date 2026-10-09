"""Gemeinsame Abhängigkeiten für API und Weboberfläche."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator

from fastapi import Request

from .config import Settings
from .db import connect
from .security import LoginLimiter, RateLimiter


def settings(request: Request) -> Settings:
    return request.app.state.settings


def limiter(request: Request) -> LoginLimiter:
    return request.app.state.limiter


def get_db(request: Request) -> Iterator[sqlite3.Connection]:
    conn = connect(request.app.state.settings.db_path)
    try:
        yield conn
    finally:
        conn.close()


def client_ip(request: Request) -> str:
    # Hinter einem Reverse Proxy setzt uvicorn (--proxy-headers) die echte Client-IP, aber nur
    # für Anfragen aus FORWARDED_ALLOW_IPS (siehe Dockerfile).
    return request.client.host if request.client else ""


def device_limiter(request: Request) -> RateLimiter:
    return request.app.state.device_limiter


def public_limiter(request: Request) -> RateLimiter:
    return request.app.state.public_limiter


def report_limiter(request: Request) -> RateLimiter:
    return request.app.state.report_limiter
