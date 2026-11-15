"""Command line: zigbee-live-map [--channel N | --demo | --replay FILE | --scan | --import-devices FILE | --update-vendors]"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from . import __version__
from .devices import DEFAULT_LIST_NAME, DeviceError, DeviceStore

DEFAULT_DATA_DIR = "~/.zigbee-live-map"
EPILOG = """examples:
  zigbee-live-map --demo                  try it without hardware (simulated network)
  zigbee-live-map --scan                  find which channel your network is on
  zigbee-live-map --channel 15            live map from the sniffer dongle
  zigbee-live-map --replay capture.pcap   replay a capture with its original timing
  zigbee-live-map --import-devices devices.csv --list Home
                                          load device names exported from your hub
"""


def parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="zigbee-live-map", description="Live animated map of a Zigbee network from a passive sniffer.",
                                 epilog=EPILOG, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--version", action="version", version=__version__)
    source = ap.add_argument_group("source")
    source.add_argument("--channel", type=int, default=11, metavar="N", help="Zigbee channel, 11 to 26 (default 11); also changeable from the page")
    source.add_argument("--demo", action="store_true", help="simulated network, no hardware needed")
    source.add_argument("--replay", metavar="PCAP", help="replay a pcap capture (linktype 802.15.4) instead of using the dongle")
    source.add_argument("--speed", type=float, default=1.0, help="speed factor for --replay and --demo (default 1)")
    source.add_argument("--pcap", metavar="OUT", help="also record the live capture to this pcap file")
    tools = ap.add_argument_group("one-shot tools")
    tools.add_argument("--scan", nargs="?", type=float, const=2.0, metavar="SECONDS", help="listen on each channel (default 2 s each), print what is there, and exit")
    tools.add_argument("--import-devices", metavar="FILE", help="merge a device list (CSV, TSV or exported JSON) into a list of known devices, and exit")
    tools.add_argument("--list", metavar="NAME", default=DEFAULT_LIST_NAME, help=f'list used by --import-devices, created if missing (default "{DEFAULT_LIST_NAME}")')
    tools.add_argument("--update-vendors", action="store_true", help="download the current IEEE registry of chip makers, and exit")
    web = ap.add_argument_group("page")
    web.add_argument("--port", type=int, default=8765, help="local port (default 8765)")
    web.add_argument("--open", action="store_true", help="open the page in your browser")
    web.add_argument("--data-dir", default=DEFAULT_DATA_DIR, metavar="DIR", help=f"where your device lists and registry updates are kept (default {DEFAULT_DATA_DIR})")
    web.add_argument("--focus", metavar="IEEE", help="start with this device watched (same as the Watch button in the page)")
    web.add_argument("--backlog", type=int, default=8000, help="events kept for pages that connect later (default 8000)")
    return ap


def run_scan(seconds: float) -> int:
    from . import sniffer

    print(f"Listening {seconds:g} s on each channel...\n")
    print(f"{'channel':>7}  {'frames':>6}  {'best RSSI':>9}  PAN ids (frames)")

    def show(row: dict) -> None:
        pans = ", ".join(f"{pan} ({n})" for pan, n in sorted(row["pans"].items(), key=lambda kv: -kv[1])) or "-"
        rssi = f"{row['best_rssi']} dBm" if row["best_rssi"] is not None else "-"
        print(f"{row['channel']:>7}  {row['frames']:>6}  {rssi:>9}  {pans}", flush=True)

    try:
        results = sniffer.scan(seconds, show)
    except sniffer.SnifferError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    busiest = max(results, key=lambda r: r["frames"])
    if busiest["frames"]:
        print(f"\nBusiest channel: {busiest['channel']}  ->  zigbee-live-map --channel {busiest['channel']}")
    else:
        print("\nNothing heard. Move the dongle closer to a router, or scan longer: --scan 5")
    return 0


def run_import(source: str, list_name: str, data_dir: Path) -> int:
    store = DeviceStore(data_dir)
    try:
        text = Path(source).read_text(encoding="utf-8-sig")
        list_id = next((item["id"] for item in store.describe() if item["name"].lower() == list_name.lower()), None) or store.create(list_name)
        count = store.import_text(list_id, text)
    except (OSError, DeviceError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f'{count} device(s) imported into the list "{store.lists[list_id]["name"]}" ({store.dir / (list_id + ".json")})')
    return 0


def run_update_vendors(data_dir: Path) -> int:
    from .vendors import Registry, VendorError

    registry = Registry(data_dir)
    print(f"Current registry: {registry.meta['entries']} prefixes, {registry.meta['date']} ({registry.meta['origin']})")
    try:
        meta = registry.refresh()
    except VendorError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"Updated from the IEEE: {meta['entries']} prefixes, {meta['date']}")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    data_dir = Path(args.data_dir).expanduser()
    if args.scan is not None:
        return run_scan(args.scan)
    if args.import_devices:
        return run_import(args.import_devices, args.list, data_dir)
    if args.update_vendors:
        return run_update_vendors(data_dir)
    if args.channel not in range(11, 27):
        print("error: --channel must be between 11 and 26", file=sys.stderr)
        return 2
    from . import server

    try:
        asyncio.run(server.serve(args))
    except KeyboardInterrupt:
        pass
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
