# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Schnuecks
"""Spiegelt docs/en und docs/de ins GitHub-Wiki.

    python tools/wiki_sync.py <Wiki-Ordner> --repo Schnuecks/rdapi --version v0.5.0

Die Doku bleibt im Repo die einzige Quelle; das Wiki ist nur eine Anzeige. Links zwischen
den Seiten werden auf Wiki-Seiten umgeschrieben, Links auf README und CHANGELOG auf das
Repo. Seiten, die es in docs/ nicht mehr gibt, werden im Wiki gelöscht.
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"

# Datei in docs/ -> Seitenname im Wiki (Bindestrich wird im Wiki als Leerzeichen gezeigt)
PAGES = {
    "en/README.md": "Home",
    "en/installation.md": "Installation",
    "en/configuration.md": "Configuration",
    "en/usage.md": "Usage",
    "en/development.md": "Development",
    "de/README.md": "Dokumentation",
    "de/installation.md": "Installation-DE",
    "de/configuration.md": "Konfiguration",
    "de/usage.md": "Bedienung",
    "de/development.md": "Entwicklung",
}
REPO_FILES = {
    "README.md": "",
    "README.de.md": "blob/main/README.de.md",
    "CHANGELOG.md": "blob/main/CHANGELOG.md",
}

LINK = re.compile(r"\]\(([^)\s]+)\)")


def rewrite_links(text: str, source: str, repo_url: str) -> str:
    """Relative Links aus docs/<lang>/<datei> auf Wiki-Seiten bzw. das Repo umbiegen."""
    folder = Path(source).parent

    def fix(match: re.Match) -> str:
        target = match.group(1)
        if re.match(r"^[a-z]+:", target) or target.startswith("#"):
            return match.group(0)
        path, _, anchor = target.partition("#")
        resolved = (Path("docs") / folder / path).as_posix()
        parts: list[str] = []
        for piece in resolved.split("/"):
            if piece == "..":
                parts.pop()
            elif piece != ".":
                parts.append(piece)
        resolved = "/".join(parts)
        suffix = f"#{anchor}" if anchor else ""
        if resolved.startswith("docs/") and resolved[5:] in PAGES:
            return f"]({PAGES[resolved[5:]]}{suffix})"
        if resolved in REPO_FILES:
            extra = REPO_FILES[resolved]
            return f"]({repo_url}{'/' + extra if extra else ''}{suffix})"
        return f"]({repo_url}/blob/main/{resolved}{suffix})"

    return LINK.sub(fix, text)


def sidebar() -> str:
    def entries(lang: str) -> str:
        return "\n".join(
            f"- [[{name.replace('-', ' ')}|{name}]]"
            for src, name in PAGES.items()
            if src.startswith(lang)
        )

    return f"**English**\n\n{entries('en/')}\n\n**Deutsch**\n\n{entries('de/')}\n"


def footer(repo_url: str, version: str) -> str:
    return (
        f"Generated from [`docs/`]({repo_url}/tree/main/docs) for {version}. "
        "Please change the documentation there, not here. · "
        f"Erzeugt aus [`docs/`]({repo_url}/tree/main/docs) für {version}. "
        "Bitte die Doku dort ändern, nicht hier.\n"
    )


def sync(wiki: Path, repo: str, version: str) -> list[str]:
    repo_url = f"https://github.com/{repo}"
    wanted = {}
    for source, name in PAGES.items():
        text = (DOCS / source).read_text(encoding="utf-8")
        wanted[f"{name}.md"] = rewrite_links(text, source, repo_url)
    wanted["_Sidebar.md"] = sidebar()
    wanted["_Footer.md"] = footer(repo_url, version)
    changed = []
    for old in wiki.glob("*.md"):
        if old.name not in wanted:
            old.unlink()
            changed.append(f"- {old.name}")
    for name, text in wanted.items():
        path = wiki / name
        if not path.exists() or path.read_text(encoding="utf-8") != text:
            path.write_text(text, encoding="utf-8", newline="\n")
            changed.append(f"+ {name}")
    return changed


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("wiki", type=Path, help="checked-out wiki repository")
    parser.add_argument("--repo", required=True, help="owner/name")
    parser.add_argument("--version", default="main")
    args = parser.parse_args()
    for line in sync(args.wiki, args.repo, args.version):
        print(line)


if __name__ == "__main__":
    main()
