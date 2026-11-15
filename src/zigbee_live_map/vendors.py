"""Who made the radio chip: the public IEEE registry of address prefixes.

The first bytes of an IEEE (EUI-64) address are a prefix that the IEEE assigns to a company:
24 bits (MA-L), 28 bits (MA-M) or 36 bits (MA-S). The holder is usually the maker of the radio
chip or module, which is often not the brand printed on the product.

A snapshot ships with the package. `refresh()` downloads the current registry from the IEEE;
it is only ever called on request (Settings page or --update-vendors), never on its own.
"""

from __future__ import annotations

import csv
import gzip
import io
import os
import ssl
import time
import urllib.request
from importlib import resources
from pathlib import Path

import truststore

SOURCES = (
    ("MA-L", "https://standards-oui.ieee.org/oui/oui.csv"),
    ("MA-M", "https://standards-oui.ieee.org/oui28/mam.csv"),
    ("MA-S", "https://standards-oui.ieee.org/oui36/oui36.csv"),
)
PREFIX_LENGTHS = (9, 7, 6)  # hex digits, longest first
SUBALLOCATED = "IEEE Registration Authority"  # the real holder is then in MA-M or MA-S
USER_FILE = "vendors.tsv.gz"
MIN_ENTRIES = 30000  # a download far below this is broken, not an update


class VendorError(RuntimeError):
    pass


def _parse_csv(text: str) -> dict[str, str]:
    table = {}
    for row in csv.reader(io.StringIO(text)):
        if len(row) >= 3 and row[0].startswith("MA-"):
            table[row[1].strip().upper()] = " ".join(row[2].split())
    return table


def _encode(table: dict[str, str], date: str) -> bytes:
    lines = [f"# source=standards-oui.ieee.org date={date} entries={len(table)}"]
    lines += [f"{prefix}\t{table[prefix]}" for prefix in sorted(table)]
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0) as fh:
        fh.write(("\n".join(lines) + "\n").encode("utf-8"))
    return buf.getvalue()


def _decode(blob: bytes) -> tuple[dict[str, str], dict]:
    text = gzip.decompress(blob).decode("utf-8")
    table, meta = {}, {"date": None}
    for line in text.splitlines():
        if line.startswith("#"):
            meta.update(part.split("=", 1) for part in line[1:].split() if "=" in part)
        elif "\t" in line:
            prefix, org = line.split("\t", 1)
            table[prefix] = org
    return table, meta


def download(timeout: float = 60) -> bytes:
    """Fetch the three IEEE registries and return them as one compact snapshot."""
    # The operating system trust store, so that this also works behind a company proxy.
    context = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    table: dict[str, str] = {}
    for _name, url in SOURCES:
        request = urllib.request.Request(url, headers={"User-Agent": "zigbee-live-map"})
        try:
            with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
                table.update(_parse_csv(response.read().decode("utf-8", errors="replace")))
        except OSError as exc:
            raise VendorError(f"could not download {url}: {exc}") from exc
    if len(table) < MIN_ENTRIES:
        raise VendorError(f"the registry looks incomplete ({len(table)} entries), keeping the current one")
    return _encode(table, time.strftime("%Y-%m-%d"))


class Registry:
    def __init__(self, data_dir: Path | None) -> None:
        self.data_dir = data_dir
        self.table: dict[str, str] = {}
        self.meta: dict = {}
        self.load()

    def load(self) -> None:
        user = self.data_dir / USER_FILE if self.data_dir else None
        if user and user.exists():
            try:
                self.table, meta = _decode(user.read_bytes())
                self.meta = {"date": meta.get("date"), "entries": len(self.table), "origin": "updated"}
                return
            except (OSError, ValueError):
                pass  # unreadable update: fall back to the bundled snapshot
        blob = resources.files("zigbee_live_map").joinpath("data/vendors.tsv.gz").read_bytes()
        self.table, meta = _decode(blob)
        self.meta = {"date": meta.get("date"), "entries": len(self.table), "origin": "bundled"}

    def lookup(self, ieee: str) -> str | None:
        digits = ieee.replace(":", "").upper()
        for length in PREFIX_LENGTHS:
            org = self.table.get(digits[:length])
            if org and org != SUBALLOCATED:
                return org
        return None

    def refresh(self) -> dict:
        if self.data_dir is None:
            raise VendorError("no data directory to store the registry in")
        blob = download()
        self.data_dir.mkdir(parents=True, exist_ok=True)
        tmp = self.data_dir / (USER_FILE + ".tmp")
        tmp.write_bytes(blob)
        os.replace(tmp, self.data_dir / USER_FILE)
        self.load()
        return self.meta


if __name__ == "__main__":  # maintainers: refresh the snapshot shipped with the package
    import sys

    Path(sys.argv[1]).write_bytes(download())
    print(f"wrote {sys.argv[1]}")
