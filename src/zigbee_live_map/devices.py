"""Known devices: named lists kept in the user's data directory, never in the repository.

Friendly names such as "Kitchen plug" are not transmitted on the Zigbee network: they only exist
in the database of a hub. So they come from the user, typed in the page or imported from a device
list exported from their own hub. Several lists can coexist (home, office, a friend's place) and
each can be switched on or off; the map uses the union of the enabled ones.

One file per list: <data dir>/lists/<id>.json
    {"name": "Home", "enabled": true, "devices": {"<ieee>": {"name": ..., "model": ..., "nwk": ...}}}
"""

from __future__ import annotations

import csv
import io
import json
import os
import re
from pathlib import Path

IEEE_RE = re.compile(r"^([0-9a-f]{2}:){7}[0-9a-f]{2}$")
ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,39}$")
DEFAULT_LIST_NAME = "My devices"
MAX_TEXT = 60
COLUMN_HINTS = {
    "ieee": ("ieee", "eui64", "eui-64", "mac"),
    "name": ("friendly", "name", "nom"),
    "model": ("model", "modèle", "modele"),
    "nwk": ("nwk", "network address", "short"),
}


class DeviceError(ValueError):
    pass


def normalise_ieee(value: str) -> str | None:
    digits = re.sub(r"[^0-9a-fA-F]", "", str(value).strip().removeprefix("0x").removeprefix("0X"))
    if len(digits) != 16:
        return None
    return ":".join(digits[i:i + 2] for i in range(0, 16, 2)).lower()


def normalise_nwk(value: str) -> str | None:
    digits = str(value).strip().lower().removeprefix("0x")
    if not re.fullmatch(r"[0-9a-f]{1,4}", digits):
        return None
    return f"0x{int(digits, 16):04x}"


def clean_entry(fields: dict) -> dict:
    """Keep only the known fields, trimmed and validated. An empty result means 'nothing to store'."""
    entry = {}
    for key in ("name", "model"):
        text = " ".join(str(fields.get(key) or "").split())[:MAX_TEXT]
        if text:
            entry[key] = text
    nwk = normalise_nwk(fields["nwk"]) if fields.get("nwk") else None
    if nwk:
        entry["nwk"] = nwk
    return entry


def _slug(name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:40].strip("-")
    return slug or "list"


def parse_table(text: str) -> dict[str, dict]:
    """A device table with a header row: CSV, semicolon or tab separated."""
    lines = text.lstrip("﻿").splitlines()
    if not lines:
        return {}
    delimiter = max("\t;,", key=lines[0].count)
    rows = list(csv.reader(lines, delimiter=delimiter))
    cols: dict[str, int] = {}
    for index, title in enumerate(rows[0]):
        low = title.strip().lower()
        for field, hints in COLUMN_HINTS.items():
            if field not in cols and any(h in low for h in hints):
                cols[field] = index
                break
    if "ieee" not in cols or "name" not in cols:
        raise DeviceError("the table needs a header row with an IEEE column and a name column")
    devices = {}
    for row in rows[1:]:
        cell = {f: (row[i].strip() if i < len(row) else "") for f, i in cols.items()}
        ieee = normalise_ieee(cell["ieee"])
        entry = clean_entry(cell)
        if ieee and entry.get("name"):
            devices[ieee] = entry
    return devices


def parse_import(text: str) -> tuple[str | None, dict[str, dict]]:
    """Accept an exported list (JSON), a bare {ieee: {...}} mapping, or a device table."""
    stripped = text.lstrip("﻿ \t\r\n")
    if not stripped.startswith("{"):
        return None, parse_table(text)
    try:
        data = json.loads(stripped)
    except ValueError as exc:
        raise DeviceError(f"not valid JSON: {exc}") from exc
    name = data.get("name") if isinstance(data.get("name"), str) and isinstance(data.get("devices"), dict) else None
    raw = data["devices"] if name is not None else data
    devices = {}
    for key, fields in raw.items() if isinstance(raw, dict) else ():
        ieee = normalise_ieee(key)
        entry = clean_entry(fields) if isinstance(fields, dict) else {}
        if ieee and entry:
            devices[ieee] = entry
    return name, devices


class DeviceStore:
    def __init__(self, data_dir: Path | None) -> None:
        """data_dir None keeps everything in memory (demo mode)."""
        self.dir = data_dir / "lists" if data_dir else None
        self.lists: dict[str, dict] = {}
        if self.dir and self.dir.is_dir():
            for path in sorted(self.dir.glob("*.json")):
                try:
                    data = json.loads(path.read_text(encoding="utf-8"))
                except (OSError, ValueError):
                    continue
                if ID_RE.match(path.stem) and isinstance(data, dict):
                    _name, devices = parse_import(json.dumps({"name": "", "devices": data.get("devices", {})}))
                    self.lists[path.stem] = {"name": str(data.get("name") or path.stem)[:MAX_TEXT],
                                             "enabled": bool(data.get("enabled", True)), "devices": devices}

    # ---- reading
    def ordered(self) -> list[tuple[str, dict]]:
        return sorted(self.lists.items(), key=lambda kv: (kv[1]["name"].lower(), kv[0]))

    def describe(self) -> list[dict]:
        return [{"id": list_id, **data} for list_id, data in self.ordered()]

    def merged(self) -> dict[str, dict]:
        """What the map uses: every device of the enabled lists; the first list in order wins a conflict."""
        names: dict[str, dict] = {}
        for _list_id, data in self.ordered():
            if data["enabled"]:
                for ieee, entry in data["devices"].items():
                    names.setdefault(ieee, entry)
        return names

    def _get(self, list_id: str) -> dict:
        if list_id not in self.lists:
            raise DeviceError("unknown list")
        return self.lists[list_id]

    # ---- writing
    def _save(self, list_id: str) -> None:
        if not self.dir:
            return
        self.dir.mkdir(parents=True, exist_ok=True)
        path = self.dir / f"{list_id}.json"
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(self.lists[list_id], indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        os.replace(tmp, path)

    def create(self, name: str) -> str:
        name = " ".join(str(name).split())[:MAX_TEXT]
        if not name:
            raise DeviceError("a list needs a name")
        base, list_id, n = _slug(name), _slug(name), 2
        while list_id in self.lists:
            list_id, n = f"{base[:36]}-{n}", n + 1
        self.lists[list_id] = {"name": name, "enabled": True, "devices": {}}
        self._save(list_id)
        return list_id

    def update(self, list_id: str, name: str | None = None, enabled: bool | None = None) -> None:
        data = self._get(list_id)
        if name is not None:
            name = " ".join(str(name).split())[:MAX_TEXT]
            if not name:
                raise DeviceError("a list needs a name")
            data["name"] = name
        if enabled is not None:
            data["enabled"] = bool(enabled)
        self._save(list_id)

    def delete(self, list_id: str) -> None:
        self._get(list_id)
        del self.lists[list_id]
        if self.dir:
            (self.dir / f"{list_id}.json").unlink(missing_ok=True)

    def set_device(self, list_id: str, ieee: str, fields: dict) -> None:
        data, ieee_n = self._get(list_id), normalise_ieee(ieee)
        if not ieee_n:
            raise DeviceError("an IEEE address is 16 hexadecimal digits")
        entry = clean_entry(fields)
        if not entry.get("name"):
            raise DeviceError("a device needs a name")
        data["devices"][ieee_n] = entry
        self._save(list_id)

    def delete_device(self, list_id: str, ieee: str) -> None:
        data = self._get(list_id)
        data["devices"].pop(normalise_ieee(ieee) or "", None)
        self._save(list_id)

    def rename(self, ieee: str, name: str) -> None:
        """Rename from the map: in the list that already knows the device, else in the default list."""
        ieee_n = normalise_ieee(ieee)
        if not ieee_n:
            return
        name = " ".join(str(name).split())[:MAX_TEXT]
        holders = [i for i, d in self.ordered() if ieee_n in d["devices"]]
        enabled = [i for i in holders if self.lists[i]["enabled"]]
        target = (enabled or holders or [None])[0]
        if not name:
            if target:
                self.delete_device(target, ieee_n)
            return
        if target is None:
            target = next((i for i, d in self.ordered() if d["enabled"]), None) or self.create(DEFAULT_LIST_NAME)
        entry = dict(self.lists[target]["devices"].get(ieee_n, {}))
        entry["name"] = name
        self.lists[target]["devices"][ieee_n] = entry
        self._save(target)

    def known(self) -> set[str]:
        """Every IEEE address that has an entry in any list, switched on or not."""
        return {ieee for data in self.lists.values() for ieee in data["devices"]}

    def fill_from_identities(self, list_id: str, found: dict[str, dict]) -> int:
        """Add the devices that no list knows yet, named after the model they announced (decrypted).

        `found` maps IEEE -> {"nwk", "manufacturer", "model"}. A device that already has an entry
        anywhere is left alone. The name is the model. When that name is taken, a device of that model
        is already known, or another device in this batch shares it, each of them gets the last bytes
        of its IEEE address appended ("Smart plug 5956"). That tail never changes for a device,
        whereas a counter ("Smart plug 2") would depend on the order the radio heard them in.
        """
        data = self._get(list_id)
        known = self.known()
        new = {ieee: item for ieee, item in sorted(found.items()) if ieee not in known}
        label = {ieee: " ".join(str(item.get("model") or item.get("manufacturer") or "Zigbee device").split())[:MAX_TEXT] for ieee, item in new.items()}
        entries = [entry for lst in self.lists.values() for entry in lst["devices"].values()]
        taken = {entry["name"].lower() for entry in entries if entry.get("name")}
        models = {entry["model"].lower() for entry in entries if entry.get("model")}   # a known twin, whatever its name became
        for ieee, item in new.items():
            twins = sum(1 for other in label.values() if other.lower() == label[ieee].lower())
            name = label[ieee]
            if twins > 1 or name.lower() in taken or name.lower() in models:
                digits = ieee.replace(":", "")
                for width in range(4, 17, 2):   # two bytes, more only if those collide as well
                    tail = f" {digits[-width:]}"
                    name = f"{label[ieee][:MAX_TEXT - len(tail)].rstrip()}{tail}"
                    if name.lower() not in taken:
                        break
            taken.add(name.lower())
            data["devices"][ieee] = clean_entry({"name": name, "model": item.get("model"), "nwk": item.get("nwk")})
        if new:
            self._save(list_id)
        return len(new)

    def import_text(self, list_id: str, text: str) -> int:
        data = self._get(list_id)
        _name, devices = parse_import(text)
        for ieee, entry in devices.items():
            data["devices"][ieee] = {**data["devices"].get(ieee, {}), **entry}
        self._save(list_id)
        return len(devices)

    def export(self, list_id: str, fmt: str) -> tuple[str, str, str]:
        """Return (file name, content type, text)."""
        data = self._get(list_id)
        if fmt == "csv":
            out = io.StringIO()
            writer = csv.writer(out, lineterminator="\n")
            writer.writerow(["name", "model", "ieee", "nwk"])
            for ieee, entry in sorted(data["devices"].items(), key=lambda kv: kv[1].get("name", "").lower()):
                writer.writerow([entry.get("name", ""), entry.get("model", ""), ieee, entry.get("nwk", "")])
            return f"{list_id}.csv", "text/csv", out.getvalue()
        if fmt == "json":
            payload = {"name": data["name"], "devices": data["devices"]}
            return f"{list_id}.json", "application/json", json.dumps(payload, indent=2, ensure_ascii=False) + "\n"
        raise DeviceError("format must be json or csv")
