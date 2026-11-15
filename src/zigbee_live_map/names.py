"""Device names: a local JSON file keyed by IEEE address, never part of the repository.

Friendly names such as "Kitchen plug" are not transmitted on the Zigbee network: they only exist
in the database of your hub. So they come from you, either typed in the page or imported from a
device list exported from your own hub (CSV or tab-separated).
"""

from __future__ import annotations

import csv
import json
import os
import re
from pathlib import Path

IEEE_RE = re.compile(r"^([0-9a-f]{2}:){7}[0-9a-f]{2}$")
COLUMN_HINTS = {
    "ieee": ("ieee", "eui64", "eui-64", "mac"),
    "name": ("friendly", "name", "nom"),
    "model": ("model", "modèle", "modele"),
    "nwk": ("nwk", "network address", "short"),
}


def normalise_ieee(value: str) -> str | None:
    digits = re.sub(r"[^0-9a-fA-F]", "", value.removeprefix("0x").removeprefix("0X"))
    if len(digits) != 16:
        return None
    return ":".join(digits[i:i + 2] for i in range(0, 16, 2)).lower()


def normalise_nwk(value: str) -> str | None:
    digits = value.strip().lower().removeprefix("0x")
    if not re.fullmatch(r"[0-9a-f]{1,4}", digits):
        return None
    return f"0x{int(digits, 16):04x}"


def load(path: Path | None) -> dict:
    if path is None or not path.exists():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    return {k.lower(): v for k, v in data.items() if isinstance(v, dict) and IEEE_RE.match(k.lower())}


def save(path: Path, names: dict) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(names, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def _columns(header: list[str]) -> dict[str, int]:
    found: dict[str, int] = {}
    for index, title in enumerate(header):
        low = title.strip().lower()
        for field, hints in COLUMN_HINTS.items():
            if field not in found and any(h in low for h in hints):
                found[field] = index
                break
    return found


def import_table(source: Path, names: dict) -> int:
    """Merge a device table (CSV, semicolon or tab separated, with a header row) into names."""
    text = source.read_text(encoding="utf-8-sig")
    first_line = text.splitlines()[0] if text.strip() else ""
    delimiter = max("\t;,", key=first_line.count)
    rows = list(csv.reader(text.splitlines(), delimiter=delimiter))
    if not rows:
        return 0
    cols = _columns(rows[0])
    if "ieee" not in cols or "name" not in cols:
        raise ValueError("the table needs a header row with an IEEE column and a name column")
    imported = 0
    for row in rows[1:]:
        def cell(field: str) -> str:
            index = cols.get(field)
            return row[index].strip() if index is not None and index < len(row) else ""

        ieee = normalise_ieee(cell("ieee"))
        if not ieee or not cell("name"):
            continue
        entry = dict(names.get(ieee, {}))
        entry["name"] = cell("name")[:60]
        if cell("model"):
            entry["model"] = cell("model")[:60]
        nwk = normalise_nwk(cell("nwk")) if cell("nwk") else None
        if nwk:
            entry["nwk"] = nwk
        names[ieee] = entry
        imported += 1
    return imported
