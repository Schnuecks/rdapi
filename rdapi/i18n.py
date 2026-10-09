"""Übersetzungen der Weboberfläche.

Die englischen Texte im Code sind zugleich die Schlüssel. rdapi/locales/<code>.json
ordnet ihnen die Übersetzung zu; fehlt ein Eintrag, bleibt der englische Text.
Platzhalter stehen in geschweiften Klammern: _("Page {n} of {pages}", n=1, pages=3).

Die Sprache gilt pro Anfrage (Cookie „lang“, sonst RDAPI_DEFAULT_LANGUAGE, sonst
Browsersprache, sonst Englisch), das Design pro Browser (Cookie „theme“, sonst
RDAPI_DEFAULT_THEME, sonst wie das System).
"""

from __future__ import annotations

import contextvars
import json
import os
from datetime import datetime
from functools import cache
from pathlib import Path
from zoneinfo import ZoneInfo

# Gleiche Sprachen und Reihenfolge wie in den anderen Projekten des Autors.
LANGUAGES = {
    "de": "Deutsch",
    "en": "English",
    "fr": "Français",
    "es": "Español",
    "it": "Italiano",
    "nl": "Nederlands",
}
SOURCE = "en"
THEMES = ("system", "light", "dark")
THEME_LABELS = {"system": "System", "light": "Light", "dark": "Dark"}
NEXT_THEME = {"system": "light", "light": "dark", "dark": "system"}
LANG_COOKIE = "lang"
THEME_COOKIE = "theme"

DATE_FORMAT = {
    "de": "%d.%m.%Y %H:%M",
    "en": "%Y-%m-%d %H:%M",
    "fr": "%d/%m/%Y %H:%M",
    "es": "%d/%m/%Y %H:%M",
    "it": "%d/%m/%Y %H:%M",
    "nl": "%d-%m-%Y %H:%M",
}

LOCALE_DIR = Path(__file__).parent / "locales"
_lang: contextvars.ContextVar[str] = contextvars.ContextVar("lang", default=SOURCE)


def _env_choice(name: str, allowed) -> str | None:
    value = os.environ.get(name, "").strip().lower()
    return value if value in allowed else None


@cache
def catalog(lang: str) -> dict[str, str]:
    path = LOCALE_DIR / f"{lang}.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}


def set_language(lang: str) -> None:
    _lang.set(lang if lang in LANGUAGES else SOURCE)


def current() -> str:
    return _lang.get()


def gettext(msg: str, **kwargs) -> str:
    lang = current()
    text = msg if lang == SOURCE else catalog(lang).get(msg) or msg
    return text.format(**kwargs) if kwargs else text


def pick_language(cookie: str | None, accept: str | None) -> str:
    if cookie in LANGUAGES:
        return cookie
    if env := _env_choice("RDAPI_DEFAULT_LANGUAGE", LANGUAGES):
        return env
    # Accept-Language: "de-DE,de;q=0.9,en;q=0.8"
    ranked = []
    for part in (accept or "").split(","):
        code, _, q = part.strip().partition(";q=")
        try:
            weight = float(q) if q else 1.0
        except ValueError:
            weight = 0.0
        ranked.append((weight, code.split("-")[0].lower()))
    for _weight, code in sorted(ranked, key=lambda r: -r[0]):
        if code in LANGUAGES:
            return code
    return SOURCE


def pick_theme(cookie: str | None) -> str:
    if cookie in THEMES:
        return cookie
    return _env_choice("RDAPI_DEFAULT_THEME", THEMES) or "system"


def fmt_dt(ts: int | None, tz: str) -> str:
    if not ts:
        return "–"
    return datetime.fromtimestamp(ts, ZoneInfo(tz)).strftime(DATE_FORMAT[current()])
