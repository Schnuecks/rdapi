from __future__ import annotations

import asyncio
import re
from pathlib import Path

import pytest
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

DOCKERFILE = Path(__file__).resolve().parent.parent / "Dockerfile"


def trusted_proxies() -> str:
    match = re.search(r"FORWARDED_ALLOW_IPS=(\S+)", DOCKERFILE.read_text(encoding="utf-8"))
    assert match, "FORWARDED_ALLOW_IPS fehlt im Dockerfile"
    return match.group(1)


def seen_client(peer: str, forwarded_for: str) -> str:
    """Client-IP, die die App sieht, wenn `peer` mit X-Forwarded-For anfragt."""
    seen = {}

    async def app(scope, receive, send):
        seen["client"] = scope["client"][0]

    scope = {
        "type": "http",
        "client": (peer, 12345),
        "headers": [(b"x-forwarded-for", forwarded_for.encode())],
    }
    asyncio.run(ProxyHeadersMiddleware(app, trusted_proxies())(scope, None, None))
    return seen["client"]


def test_dockerfile_does_not_trust_everyone():
    assert "*" not in trusted_proxies()
    assert "--forwarded-allow-ips" not in DOCKERFILE.read_text(encoding="utf-8")


@pytest.mark.parametrize("proxy", ["172.20.0.5", "10.1.2.3", "192.168.1.10", "127.0.0.1"])
def test_forwarded_ip_from_private_proxy_is_used(proxy):
    assert seen_client(proxy, "203.0.113.7") == "203.0.113.7"


def test_forwarded_ip_from_public_address_is_ignored():
    # Wer den Server direkt aus dem Internet erreicht, kann sich keine Adresse ausdenken.
    assert seen_client("198.51.100.20", "10.0.0.1") == "198.51.100.20"


def test_spoofed_entry_before_the_proxy_is_ignored():
    # Traefik hängt die echte Adresse hinten an; davor stehende Einträge kommen vom Client.
    assert seen_client("172.20.0.5", "1.2.3.4, 203.0.113.7") == "203.0.113.7"
