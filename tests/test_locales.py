"""Every translation is checked against the English reference, so a contributor sees at once what is missing."""
import json
import re
from importlib import resources

import pytest

LOCALES = resources.files("zigbee_live_map").joinpath("static", "locales")
REFERENCE = json.loads(LOCALES.joinpath("en.json").read_text(encoding="utf-8"))
OTHERS = sorted(p.name for p in LOCALES.iterdir() if p.name.endswith(".json") and p.name != "en.json")
PLACEHOLDER = re.compile(r"\{(\w+)\}")


def test_reference_is_flat_text():
    assert REFERENCE["_name"] == "English"
    assert all(isinstance(v, str) and v for v in REFERENCE.values())


@pytest.mark.parametrize("name", OTHERS)
def test_translation_matches_the_reference(name):
    strings = json.loads(LOCALES.joinpath(name).read_text(encoding="utf-8"))
    assert strings.get("_name"), "a translation names itself in its own language under _name"
    unknown = sorted(set(strings) - set(REFERENCE))
    assert not unknown, f"keys that do not exist in en.json: {unknown}"
    for key, text in strings.items():
        assert isinstance(text, str) and text, key
        assert set(PLACEHOLDER.findall(text)) == set(PLACEHOLDER.findall(REFERENCE[key])), f"{key}: placeholders differ from en.json"


def test_french_is_complete():
    strings = json.loads(LOCALES.joinpath("fr.json").read_text(encoding="utf-8"))
    assert sorted(set(REFERENCE) - set(strings)) == []


def test_every_key_used_by_the_pages_exists():
    static = resources.files("zigbee_live_map").joinpath("static")
    used = set()
    for page in ("index.html", "devices.html", "common.js"):
        text = static.joinpath(page).read_text(encoding="utf-8")
        used |= set(re.findall(r'data-i18n(?:-aria|-placeholder)?="([\w.]+)"', text))
        used |= set(re.findall(r'\bt\("([\w.]+)"', text))
    literal = {k for k in used if not k.endswith(".")}
    assert sorted(literal - set(REFERENCE)) == []
