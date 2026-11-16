"""Hue Bridge: what the hub itself knows about its Zigbee devices, to put next to what the sniffer hears.

A sniffer cannot read names, models or rooms, and cannot tell a device that is gone from one that is
merely quiet. The bridge can: it keeps authoritative names, models, rooms, and a reachability status per
device (CLIP v2: `device`, `zigbee_connectivity`, `room`, `device_power`). The tool reads those, joins them
to the map on the IEEE address, and shows them as a separate "from the hub" group. The bridge gives no
link-quality figure (no LQI, no RSSI): that stays out.

Trust, in four rules, because the bridge speaks HTTPS with a certificate nobody can check against a public
authority:
- when a bridge is first set up (pairing, or typing an existing key), the SHA-256 fingerprint of the certificate
  it presents is recorded, and its common name must equal the bridge id it announces;
- every later request must present that same certificate (aiohttp's `Fingerprint`), checked while connecting,
  before anything, the application key included, is sent. A different one is refused, and the user forgets the
  bridge and sets it up again;
- only private, link-local and loopback addresses are ever contacted, and the address checked is the one dialled;
- nothing is contacted until the user asks (discover, pair, enter a key, refresh), apart from a bridge set up
  before, which is read at start-up and every 30 seconds.

The application key is a secret. It lives in <data dir>/hue.json (owner only), in memory in demo mode, and it
never appears in an answer, a WebSocket message, a log line or an error text: everything the pages get is built
field by field from `status()` and `view()`, and every failure is turned into a fixed sentence.
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import os
import re
import socket
import ssl
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Awaitable, Callable

import aiohttp
from cryptography import x509
from cryptography.x509.oid import NameOID

from .devices import DeviceError, normalise_ieee

SERVICE = "_hue._tcp.local."
REFRESH_SECONDS = 30.0      # how often a set-up bridge is read again
PAIR_INTERVAL = 2.0         # between two pairing attempts while the link button is not pressed
PAIR_TIMEOUT = 30.0         # how long pairing waits for the button
DISCOVER_SECONDS = 3.0
REQUEST_TIMEOUT = 10.0
MAX_BODY = 4 * 1024 * 1024
DEFAULT_PORT = 443
DEVICE_TYPE = "zigbee-live-map#diagnostic"
RESOURCES = ("device", "zigbee_connectivity", "room", "device_power")
BRIDGE_ID_RE = re.compile(r"^[0-9a-fA-F]{16}$")
KEY_RE = re.compile(r"^[A-Za-z0-9_-]{8,128}$")
HOST_RE = re.compile(r"^[A-Za-z0-9._:\[\]%-]{1,255}$")
FINGERPRINT_RE = re.compile(r"^[0-9a-f]{64}$")
MAX_TEXT = 80

Notify = Callable[[], Awaitable[None]]


class HueError(DeviceError):
    """Always a plain sentence for the user: never the key, never a raw reply or exception text."""


# ------------------------------------------------------------------------------------------ addresses

def check_address(address: str) -> str:
    """Only the local network: private, link-local or loopback. The bridge endpoint must not reach arbitrary hosts."""
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        raise HueError("That is not an address this tool can reach.") from None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if ip.is_unspecified or ip.is_multicast or not (ip.is_private or ip.is_link_local or ip.is_loopback):
        raise HueError("This tool only contacts a bridge on your own network: that address is not a private, link-local or loopback one.")
    return address


def split_host(text: object) -> tuple[str, int]:
    """'10.0.0.5', '10.0.0.5:8443', 'bridge.local' or '[fe80::1]:443' into (host, port)."""
    text = str(text or "").strip()
    if not HOST_RE.match(text):
        raise HueError("Type the address of the bridge, such as 10.0.0.5 or bridge.local.")
    port: str | None = None
    if text.startswith("["):
        match = re.fullmatch(r"\[([^\]]+)\](?::(\d+))?", text)
        if not match:
            raise HueError("Type the address of the bridge, such as 10.0.0.5 or bridge.local.")
        host, port = match.group(1), match.group(2)
    elif text.count(":") == 1:
        host, _, port = text.partition(":")
    else:
        host = text     # a bare IPv6 address has no port
    number = int(port) if port else DEFAULT_PORT
    if not host or not 1 <= number <= 65535:
        raise HueError("Type the address of the bridge, such as 10.0.0.5 or bridge.local.")
    return host, number


async def resolve(host: str, port: int) -> list[str]:
    infos = await asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return list(dict.fromkeys(info[4][0] for info in infos))


async def target_address(host: str, port: int) -> str:
    """The one address to dial, always a local one.

    A bridge's name often resolves to a public IPv6 address next to its private ones (a home router hands those
    out), so a name is not refused for having one: the public addresses are simply never dialled. A name with no
    local address at all is refused, and so is a literal public address.
    """
    try:
        ipaddress.ip_address(host)
        literal = True
    except ValueError:
        literal = False
    if literal:
        return check_address(host)
    try:
        addresses = await resolve(host, port)
    except OSError:
        raise HueError("That name does not resolve. Try the bridge's IP address.") from None
    if not addresses:
        raise HueError("That name does not resolve. Try the bridge's IP address.")
    local = []
    for address in addresses:
        try:
            local.append(check_address(address))
        except HueError:
            continue
    if not local:
        check_address(addresses[0])     # raises with the plain "not on your own network" sentence
    return next((a for a in local if ":" not in a), local[0])


def _base(ip: str, port: int) -> str:
    return f"https://[{ip.replace('%', '%25')}]:{port}" if ":" in ip else f"https://{ip}:{port}"


# ------------------------------------------------------------------------------------------ TLS

async def fetch_certificate(ip: str, port: int) -> bytes:
    """The certificate (DER) an address presents. Nothing is checked here: it is only read, to be pinned and compared."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    _reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port, ssl=context), REQUEST_TIMEOUT)
    try:
        der = writer.get_extra_info("ssl_object").getpeercert(binary_form=True)
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except (OSError, ssl.SSLError):
            pass
    if not der:
        raise HueError("The bridge did not present a certificate.")
    return der


def describe_certificate(der: bytes) -> tuple[str, str | None]:
    """(SHA-256 fingerprint as hex, common name)."""
    try:
        names = x509.load_der_x509_certificate(der).subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        common_name = str(names[0].value) if names else None
    except ValueError:
        common_name = None
    return hashlib.sha256(der).hexdigest(), common_name


class Link:
    """One session with a bridge, pinned to the certificate recorded for it. Redirects are never followed."""

    def __init__(self, ip: str, port: int, fingerprint: str, key: str | None = None) -> None:
        self.base, self.key = _base(ip, port), key
        self.fingerprint = bytes.fromhex(fingerprint)
        self.session: aiohttp.ClientSession | None = None

    async def __aenter__(self) -> "Link":
        connector = aiohttp.TCPConnector(ssl=aiohttp.Fingerprint(self.fingerprint))
        self.session = aiohttp.ClientSession(connector=connector, timeout=aiohttp.ClientTimeout(total=REQUEST_TIMEOUT))
        return self

    async def __aexit__(self, *_exc) -> None:
        if self.session:
            await self.session.close()

    async def call(self, method: str, path: str, body: Any = None) -> tuple[int, Any]:
        headers = {"hue-application-key": self.key} if self.key else {}
        assert self.session is not None
        async with self.session.request(method, self.base + path, json=body, headers=headers, allow_redirects=False) as response:
            raw = b""
            async for chunk in response.content.iter_chunked(64 * 1024):   # a real bridge sends its device list in many pieces
                raw += chunk
                if len(raw) > MAX_BODY:
                    raise HueError("The bridge answered with far more than expected.")
            try:
                return response.status, json.loads(raw)
            except ValueError:
                return response.status, None


def plain(exc: BaseException) -> HueError:
    """Every failure becomes a fixed sentence: raw exception text can carry addresses, replies, or worse."""
    if isinstance(exc, HueError):
        return exc
    if isinstance(exc, aiohttp.ServerFingerprintMismatch):
        return HueError("The bridge now presents a different certificate than the one recorded when it was set up. If you replaced or reset it, "
                        "forget the bridge and set it up again. If you did not, do not continue.")
    if isinstance(exc, (asyncio.TimeoutError, TimeoutError)):
        return HueError("The bridge did not answer in time.")
    if isinstance(exc, (aiohttp.ClientError, OSError, ssl.SSLError)):
        return HueError("Could not reach the bridge at that address.")
    return HueError("Something unexpected went wrong talking to the bridge.")


def _text(value: object) -> str | None:
    if isinstance(value, bool) or not isinstance(value, (str, int, float)):
        return None
    return " ".join(str(value).split())[:MAX_TEXT] or None


@dataclass
class Probe:
    ip: str
    port: int
    fingerprint: str
    bridge_id: str
    name: str


async def probe(host_text: object) -> Probe:
    """First contact: pin the certificate, read who the bridge says it is, and make sure the certificate agrees."""
    host, port = split_host(host_text)
    ip = await target_address(host, port)
    try:
        fingerprint, common_name = describe_certificate(await fetch_certificate(ip, port))
        async with Link(ip, port, fingerprint) as link:
            status, config = await link.call("GET", "/api/0/config")
    except Exception as exc:
        raise plain(exc) from None
    bridge_id = config.get("bridgeid") if status == 200 and isinstance(config, dict) else None
    if not isinstance(bridge_id, str) or not BRIDGE_ID_RE.match(bridge_id):
        raise HueError("That does not look like a Hue bridge.")
    if not common_name or common_name.lower() != bridge_id.lower():
        raise HueError("The certificate this bridge presents has a common name that does not match the bridge id it announces: not trusted.")
    return Probe(ip, port, fingerprint, bridge_id.upper(), _text(config.get("name")) or "Hue Bridge")


# ------------------------------------------------------------------------------------------ what the bridge knows

def build_devices(resources: dict) -> dict[str, dict]:
    """Join the four CLIP v2 resources on the IEEE address. Missing or dangling references are tolerated, not fatal."""
    def rows(name: str) -> list[dict]:
        data = (resources.get(name) or {}).get("data")
        return [row for row in data if isinstance(row, dict)] if isinstance(data, list) else []

    def owner(row: dict) -> str | None:
        rid = (row.get("owner") or {}).get("rid") if isinstance(row.get("owner"), dict) else None
        return rid if isinstance(rid, str) else None

    rooms: dict[str, str | None] = {}
    for room in rows("room"):
        name = _text((room.get("metadata") or {}).get("name")) if isinstance(room.get("metadata"), dict) else None
        for child in room.get("children") or []:
            if isinstance(child, dict) and isinstance(child.get("rid"), str):
                rooms.setdefault(child["rid"], name)
    batteries: dict[str, dict] = {}
    for row in rows("device_power"):
        state = row.get("power_state") if isinstance(row.get("power_state"), dict) else {}
        level = state.get("battery_level")
        if owner(row) and isinstance(level, int) and not isinstance(level, bool) and 0 <= level <= 100:
            batteries[owner(row)] = {"level": level, "state": _text(state.get("battery_state"))}
    links: dict[str, tuple[str, str]] = {}
    for row in rows("zigbee_connectivity"):
        ieee = normalise_ieee(str(row.get("mac_address") or ""))
        status = row.get("status")
        if owner(row) and ieee:
            links[owner(row)] = (ieee, status if isinstance(status, str) and re.fullmatch(r"[a-z_]{1,40}", status) else "unknown")
    devices: dict[str, dict] = {}
    for device in rows("device"):
        did = device.get("id")
        if not isinstance(did, str) or did not in links:
            continue    # no id, or no Zigbee address (a Hue Tap, say): nothing to join on
        meta = device.get("metadata") if isinstance(device.get("metadata"), dict) else {}
        product = device.get("product_data") if isinstance(device.get("product_data"), dict) else {}
        ieee, status = links[did]
        devices[ieee] = {"name": _text(meta.get("name")), "product": _text(product.get("product_name")), "model": _text(product.get("model_id")),
                         "maker": _text(product.get("manufacturer_name")), "type": _text(meta.get("archetype")) or _text(product.get("product_archetype")),
                         "room": rooms.get(did), "status": status, "battery": batteries.get(did)}
    return devices


def bridge_channel(resources: dict) -> int | None:
    """The Zigbee channel (11 to 26) of the bridge's own network, or None. Only the bridge's entry carries it: {"channel": {"value": "channel_20"}}."""
    data = (resources.get("zigbee_connectivity") or {}).get("data")
    for row in data if isinstance(data, list) else []:
        channel = row.get("channel") if isinstance(row, dict) else None
        value = channel.get("value") if isinstance(channel, dict) else None
        match = re.fullmatch(r"channel_(\d{2})", value) if isinstance(value, str) else None
        if match and 11 <= int(match.group(1)) <= 26:
            return int(match.group(1))
    return None


# ------------------------------------------------------------------------------------------ discovery

def parse_service(record: dict) -> dict | None:
    """One mDNS answer into {name, bridgeId, host}, or None when it offers no address on the local network."""
    props = {(k.decode("utf-8", "replace") if isinstance(k, bytes) else str(k)).lower(): v for k, v in (record.get("properties") or {}).items()}
    raw = props.get("bridgeid")
    raw = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else raw
    bridge_id = raw.upper() if isinstance(raw, str) and BRIDGE_ID_RE.match(raw) else None
    port = record.get("port") if isinstance(record.get("port"), int) else DEFAULT_PORT
    for address in sorted(record.get("addresses") or [], key=lambda a: ":" in a):   # IPv4 first
        try:
            check_address(address)
        except HueError:
            continue
        host = address if port == DEFAULT_PORT else (f"[{address}]:{port}" if ":" in address else f"{address}:{port}")
        name = _text(str(record.get("name") or "").removesuffix("." + SERVICE)) or "Hue Bridge"
        return {"name": name, "bridgeId": bridge_id, "host": host}
    return None


async def browse_mdns(timeout: float) -> list[dict]:
    """Browse `_hue._tcp.local.` for `timeout` seconds. Thin on purpose: parsing and filtering are in parse_service."""
    from zeroconf import ServiceStateChange
    from zeroconf.asyncio import AsyncServiceBrowser, AsyncServiceInfo, AsyncZeroconf

    azc, names = AsyncZeroconf(), set()

    def on_change(zeroconf, service_type, name, state_change) -> None:
        if state_change is not ServiceStateChange.Removed:
            names.add(name)

    browser = AsyncServiceBrowser(azc.zeroconf, SERVICE, handlers=[on_change])
    try:
        await asyncio.sleep(timeout)
        records = []
        for name in sorted(names):
            info = AsyncServiceInfo(SERVICE, name)
            if await info.async_request(azc.zeroconf, 2000):
                records.append({"name": name, "addresses": info.parsed_addresses(), "port": info.port, "properties": dict(info.properties)})
        return records
    finally:
        await browser.async_cancel()
        await azc.async_close()


async def discover() -> list[dict]:
    """The bridges answering on the network, only when the user asked."""
    try:
        records = await browse_mdns(DISCOVER_SECONDS)
    except Exception:
        raise HueError("The search of the network could not run here.") from None
    found = {}
    for record in records:
        service = parse_service(record)
        if service:
            found[service["host"]] = service
    return sorted(found.values(), key=lambda bridge: (bridge["name"], bridge["host"]))


# ------------------------------------------------------------------------------------------ the service

def _valid_config(data: Any) -> dict | None:
    if not isinstance(data, dict):
        return None
    try:
        split_host(data.get("host"))
    except HueError:
        return None
    ok = (isinstance(data.get("key"), str) and KEY_RE.match(data["key"]) and isinstance(data.get("fingerprint"), str) and FINGERPRINT_RE.match(data["fingerprint"])
          and isinstance(data.get("bridge_id"), str) and BRIDGE_ID_RE.match(data["bridge_id"]))
    if not ok:
        return None
    return {"host": str(data["host"]).strip(), "bridge_id": data["bridge_id"].upper(), "name": _text(data.get("name")) or "Hue Bridge",
            "key": data["key"], "fingerprint": data["fingerprint"], "added": data.get("added")}


class HueService:
    """One bridge at most: its stored setup, what it said last, and the two background jobs (pairing, periodic read)."""

    def __init__(self, data_dir: Path | None, on_change: Notify | None = None) -> None:
        """data_dir None keeps everything in memory (demo mode). Loading the file contacts nothing."""
        self.path = (data_dir / "hue.json") if data_dir else None
        self.on_change = on_change
        self.config: dict | None = None
        if self.path and self.path.is_file():
            try:
                self.config = _valid_config(json.loads(self.path.read_text(encoding="utf-8")))
            except (OSError, ValueError):
                pass
        self.devices: dict[str, dict] = {}
        self.channel: int | None = None     # the Zigbee channel of the bridge's network, from its last read
        self.last_read: float | None = None
        self.error: str | None = None
        self.pairing: str | None = None     # "waiting" for the link button, or "timeout"
        self._lock = asyncio.Lock()
        self._loop_task: asyncio.Task | None = None
        self._pair_task: asyncio.Task | None = None

    @property
    def configured(self) -> bool:
        return self.config is not None

    @property
    def _tasks(self) -> list[asyncio.Task]:
        return [task for task in (self._loop_task, self._pair_task) if task is not None and not task.done()]

    # ---- what the pages may know: an allowlist, never "the record minus the key"
    def status(self) -> dict:
        config = self.config
        return {"configured": config is not None, "name": config["name"] if config else None, "bridgeId": config["bridge_id"] if config else None,
                "lastRead": self.last_read, "error": self.error, "pairing": self.pairing, "channel": self.channel, "deviceCount": len(self.devices)}

    def view(self) -> dict:
        return {**self.status(), "devices": self.devices}

    def fallback_names(self) -> dict[str, dict]:
        """The bridge's names, for devices no list names. The caller lets the user's lists win; nothing is written anywhere."""
        return {ieee: {"name": device["name"]} for ieee, device in self.devices.items() if device.get("name")}

    async def _changed(self) -> None:
        if self.on_change:
            await self.on_change()

    # ---- setting up
    async def start_pairing(self, host: object) -> dict:
        """Check the bridge, then ask it for a key every PAIR_INTERVAL until the link button is pressed or PAIR_TIMEOUT passes."""
        self._require_free()
        self.error, self.pairing = None, "waiting"
        try:
            found = await probe(host)
        except HueError:
            self.pairing = None
            raise
        self._pair_task = asyncio.create_task(self._pair(found, str(host).strip()))
        await self._changed()
        return self.status()

    async def set_key(self, host: object, key: object) -> dict:
        """An application key the user already has: checked against the bridge before it is kept."""
        self._require_free()
        key = str(key or "").strip()
        if not KEY_RE.match(key):
            raise HueError("That does not look like an application key.")
        found = await probe(host)
        try:
            async with Link(found.ip, found.port, found.fingerprint, key) as link:
                status, _data = await link.call("GET", "/clip/v2/resource/device")
        except Exception as exc:
            raise plain(exc) from None
        if status in (401, 403):
            raise HueError("The bridge did not accept that application key.")
        if status != 200:
            raise HueError("The bridge answered in a way this tool does not understand.")
        await self._adopt(found, str(host).strip(), key)
        return self.status()

    def _require_free(self) -> None:
        if self.config is not None:
            raise HueError("A bridge is already set up. Forget it first to set up another.")
        if self.pairing == "waiting":
            raise HueError("Pairing is under way. Press the link button on the bridge, or forget the bridge to cancel.")

    async def _pair(self, found: Probe, host: str) -> None:
        deadline = time.monotonic() + PAIR_TIMEOUT
        try:
            async with Link(found.ip, found.port, found.fingerprint) as link:
                while True:
                    _status, data = await link.call("POST", "/api", {"devicetype": DEVICE_TYPE})
                    item = data[0] if isinstance(data, list) and data and isinstance(data[0], dict) else {}
                    success = item.get("success") if isinstance(item.get("success"), dict) else None
                    error = item.get("error") if isinstance(item.get("error"), dict) else None
                    if success and isinstance(success.get("username"), str) and KEY_RE.match(success["username"]):
                        key = success["username"]
                        break
                    if not error or error.get("type") != 101:
                        raise HueError("The bridge refused the pairing request." if error else "That does not look like a Hue bridge.")
                    if time.monotonic() >= deadline:
                        self.pairing = "timeout"
                        await self._changed()
                        return
                    await asyncio.sleep(PAIR_INTERVAL)
            await self._adopt(found, host, key)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self.pairing, self.error = None, str(plain(exc))
            await self._changed()

    async def _adopt(self, found: Probe, host: str, key: str) -> None:
        self.config = {"host": host, "bridge_id": found.bridge_id, "name": found.name, "key": key, "fingerprint": found.fingerprint, "added": int(time.time())}
        self.error, self.devices, self.channel, self.last_read = None, {}, None, None
        self._save()
        await self.refresh()
        if self.pairing is not None:    # pairing is over only once the bridge was read: no "set up, never read" in between
            self.pairing = None
            await self._changed()
        self.start(read_now=False)      # just read: the next one is due in REFRESH_SECONDS

    def _save(self) -> None:
        if not self.path or self.config is None:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".json.tmp")
        tmp.unlink(missing_ok=True)
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)    # owner only from the first byte, not after the fact
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(self.config, indent=2) + "\n")
        os.replace(tmp, self.path)

    # ---- reading
    def start(self, read_now: bool = True) -> None:
        """Read the bridge (now, unless it was just read) and every REFRESH_SECONDS. Does nothing when no bridge is set up."""
        if self.config is not None and (self._loop_task is None or self._loop_task.done()):
            self._loop_task = asyncio.create_task(self._loop(read_now))

    async def _loop(self, read_now: bool) -> None:
        if not read_now:
            await asyncio.sleep(REFRESH_SECONDS)
        while True:
            await self.refresh()
            await asyncio.sleep(REFRESH_SECONDS)

    async def refresh(self) -> None:
        config = self.config
        if config is None:
            return
        async with self._lock:
            try:
                host, port = split_host(config["host"])
                ip = await target_address(host, port)      # looked up and checked again each time
                got = {}
                async with Link(ip, port, config["fingerprint"], config["key"]) as link:
                    for resource in RESOURCES:
                        status, data = await link.call("GET", f"/clip/v2/resource/{resource}")
                        if status in (401, 403):
                            raise HueError("The bridge no longer accepts the application key. Forget the bridge and set it up again.")
                        if status != 200 or not isinstance(data, dict):
                            raise HueError("The bridge answered in a way this tool does not understand.")
                        got[resource] = data
                devices, channel, error = build_devices(got), bridge_channel(got), None
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                devices, channel, error = None, None, str(plain(exc))
            if self.config is not config:
                return      # forgotten while the bridge was being read
            if devices is not None:
                self.devices, self.channel, self.last_read = devices, channel, time.time()
            self.error = error
        await self._changed()

    # ---- forgetting
    async def _cancel(self) -> None:
        current = asyncio.current_task()
        tasks = [task for task in self._tasks if task is not current]
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

    async def forget(self) -> dict:
        """Drop the bridge: key, certificate, names, and any pairing under way."""
        await self._cancel()
        self.config, self.devices, self.channel, self.last_read, self.error, self.pairing = None, {}, None, None, None, None
        if self.path:
            self.path.unlink(missing_ok=True)
        await self._changed()
        return self.status()

    async def stop(self) -> None:
        await self._cancel()
