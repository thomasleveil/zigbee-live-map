"""Network keys the user knows, one per network (PAN), kept so a known network decrypts next time.

A network key is a secret: this store lives in the user's data directory, never in the repository,
and is kept in memory only in demo mode. Stored as <data dir>/keys.json:
    { "<pan>": {"key": "<32 hex>", "label": "<name>", "added": <unix seconds>} }

The whole point is cross-session analysis: enter (or recover) a key once, and every later session on
that PAN decrypts its own traffic automatically.
"""

from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path

from .devices import DeviceError

PAN_RE = re.compile(r"^0x[0-9a-f]{4}$")
MAX_LABEL = 60


def normalise_key(value: str) -> bytes:
    raw = re.sub(r"[^0-9a-fA-F]", "", str(value))
    try:
        key = bytes.fromhex(raw)
    except ValueError:
        raise DeviceError("the network key must be hexadecimal") from None
    if len(key) != 16:
        raise DeviceError("the network key must be 16 bytes (32 hexadecimal characters)")
    return key


def normalise_pan(value: str) -> str:
    text = str(value).strip().lower()
    if not text.startswith("0x"):
        text = "0x" + text
    if not PAN_RE.match(text):
        raise DeviceError("a PAN id looks like 0x1a62")
    return text


class KeyStore:
    def __init__(self, data_dir: Path | None) -> None:
        """data_dir None keeps everything in memory (demo mode)."""
        self.path = (data_dir / "keys.json") if data_dir else None
        self.keys: dict[str, dict] = {}
        if self.path and self.path.is_file():
            try:
                data = json.loads(self.path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                return
            if isinstance(data, dict):
                for pan, rec in data.items():
                    pan = str(pan).lower()
                    if not PAN_RE.match(pan) or not isinstance(rec, dict):
                        continue
                    try:
                        key = bytes.fromhex(str(rec.get("key", "")))
                    except ValueError:
                        continue
                    if len(key) == 16:
                        self.keys[pan] = {"key": key.hex(), "label": str(rec.get("label") or "")[:MAX_LABEL], "added": rec.get("added")}

    def describe(self) -> list[dict]:
        return [{"pan": pan, "label": rec["label"], "key": rec["key"]} for pan, rec in sorted(self.keys.items())]

    def get(self, pan: str | None) -> bytes | None:
        rec = self.keys.get((pan or "").lower())
        return bytes.fromhex(rec["key"]) if rec else None

    def set(self, pan: str, key: str, label: str = "") -> str:
        pan = normalise_pan(pan)
        self.keys[pan] = {"key": normalise_key(key).hex(), "label": " ".join(str(label).split())[:MAX_LABEL], "added": int(time.time())}
        self._save()
        return pan

    def delete(self, pan: str) -> None:
        self.keys.pop((pan or "").lower(), None)
        self._save()

    def _save(self) -> None:
        if not self.path:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(self.keys, indent=2) + "\n", encoding="utf-8")
        os.replace(tmp, self.path)
        try:
            os.chmod(self.path, 0o600)   # network keys are secrets: owner read/write only
        except OSError:
            pass
