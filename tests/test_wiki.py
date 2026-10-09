"""Spiegeln der Doku ins Wiki (tools/wiki_sync.py)."""

from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import wiki_sync  # noqa: E402

REPO = "https://github.com/Schnuecks/rdapi"


def test_every_doc_has_a_wiki_page():
    files = {p.relative_to(wiki_sync.DOCS).as_posix() for p in wiki_sync.DOCS.glob("*/*.md")}
    assert files == set(wiki_sync.PAGES)


def test_links_are_rewritten():
    text = (
        "[a](configuration.md#settings) [b](../de/installation.md) [c](README.md) "
        "[d](../../CHANGELOG.md) [e](../../README.de.md) [f](#backups) "
        "[g](https://example.com/x.md) [h](../../compose.yaml)"
    )
    out = wiki_sync.rewrite_links(text, "en/usage.md", REPO)
    assert "[a](Configuration#settings)" in out
    assert "[b](Installation-DE)" in out
    assert "[c](Home)" in out
    assert f"[d]({REPO}/blob/main/CHANGELOG.md)" in out
    assert f"[e]({REPO}/blob/main/README.de.md)" in out
    assert "[f](#backups)" in out
    assert "[g](https://example.com/x.md)" in out
    assert f"[h]({REPO}/blob/main/compose.yaml)" in out


def test_sync_writes_pages_without_relative_md_links(tmp_path):
    (tmp_path / "Old-page.md").write_text("weg", encoding="utf-8")
    changed = wiki_sync.sync(tmp_path, "Schnuecks/rdapi", "v9.9.9")
    assert "- Old-page.md" in changed
    names = {p.name for p in tmp_path.glob("*.md")}
    assert names == {f"{n}.md" for n in wiki_sync.PAGES.values()} | {"_Sidebar.md", "_Footer.md"}
    for page in tmp_path.glob("*.md"):
        text = page.read_text(encoding="utf-8")
        assert not re.search(r"\]\((?!https?:)[^)#]*\.md", text), page.name
    assert "v9.9.9" in (tmp_path / "_Footer.md").read_text(encoding="utf-8")
    # Zweiter Lauf ändert nichts.
    assert wiki_sync.sync(tmp_path, "Schnuecks/rdapi", "v9.9.9") == []
