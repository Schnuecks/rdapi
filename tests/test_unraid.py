"""Die Unraid-Vorlage muss zum Image und zur Compose-Datei passen."""

import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TEMPLATE = ET.parse(ROOT / "unraid" / "rdapi.xml").getroot()


def _config(target: str) -> ET.Element:
    return next(c for c in TEMPLATE.iter("Config") if c.get("Target") == target)


def test_template_uses_published_image_and_port():
    assert TEMPLATE.findtext("Repository") == "ghcr.io/schnuecks/rdapi:latest"
    assert _config("21114").get("Type") == "Port"
    assert "[PORT:21114]" in TEMPLATE.findtext("WebUI")
    assert _config("/data").get("Mode") == "rw"


def test_template_runs_hardened_like_compose():
    extra = TEMPLATE.findtext("ExtraParams")
    for flag in (
        "--user 99:100",
        "--read-only",
        "--tmpfs /tmp",
        "--cap-drop ALL",
        "no-new-privileges:true",
    ):
        assert flag in extra


def test_template_secret_is_masked_and_never_trusts_every_proxy():
    assert _config("RDAPI_SECRET_KEY").get("Mask") == "true"
    assert "*" not in (_config("FORWARDED_ALLOW_IPS").text or "")


def test_template_variables_are_documented():
    documented = (ROOT / "docs" / "en" / "configuration.md").read_text(encoding="utf-8")
    for config in TEMPLATE.iter("Config"):
        if config.get("Type") == "Variable":
            assert f"`{config.get('Target')}`" in documented, config.get("Target")
