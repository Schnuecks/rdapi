"""Lean self-hosted API server for the RustDesk app."""

import os


def _version() -> str:
    """Version aus dem Image: bei Releases der Tag (v0.3.0 -> 0.3.0), sonst dev-<Commit>."""
    v = os.environ.get("RDAPI_VERSION", "").strip() or "dev"
    if v.startswith("dev-"):
        return v[:11]  # dev- plus 7 Zeichen der Commit-Kennung, wie auf GitHub
    return v.removeprefix("v")


__version__ = _version()
