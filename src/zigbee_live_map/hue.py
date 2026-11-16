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
- only the local network is ever contacted: an explicit list of ranges (below), not Python's wider idea of "private", and
  the address checked is the one dialled. Loopback only counts when nobody signs in (a loopback bind with no password: `Access.local`), so that a signed-in
  user, from the network or through a proxy, cannot use the bridge form to probe this computer's own ports;
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
DISCOVER_SECONDS = 3.0      # how long the network is listened to
DISCOVER_DEADLINE = 6.0     # the whole search, listening and follow-ups included, whatever the network announces
MAX_ANNOUNCED = 16          # names followed up: a home has a handful of bridges, a hostile network can announce thousands
RESOLVE_TIMEOUT = 5.0       # looking a name up
REQUEST_TIMEOUT = 10.0
MAX_BODY = 4 * 1024 * 1024
DEFAULT_PORT = 443
DEVICE_TYPE = "zigbee-live-map#diagnostic"
RESOURCES = ("device", "zigbee_connectivity", "room", "device_power")
BRIDGE_ID_RE = re.compile(r"^[0-9a-fA-F]{16}$")
KEY_RE = re.compile(r"^[A-Za-z0-9_-]{8,128}$")
HOST_RE = re.compile(r"^[A-Za-z0-9._:\[\]%-]{1,255}$")
LOCAL_NETWORKS = tuple(ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16",     # IPv4: private use, link-local
    "fc00::/7", "fe80::/10"))                                               # IPv6: unique local, link-local
# Python's `is_private` also says yes to 198.18.0.0/15 (fake-IP proxies forward it to the internet), Teredo (2001::/32), NAT64
# (64:ff9b:1::/48), the documentation ranges and more: it must not decide.
FINGERPRINT_RE = re.compile(r"^[0-9a-f]{64}$")
MAX_TEXT = 80

Notify = Callable[[], Awaitable[None]]


class HueError(DeviceError):
    """Always a plain sentence for the user: never the key, never a raw reply or exception text."""


# ------------------------------------------------------------------------------------------ addresses

SCOPED = "Type the bridge's IPv4 address: an IPv6 address with a % and a network name, such as fe80::1%en0, cannot be used here."


def check_address(address: str, loopback: bool = True) -> str:
    """Only the local network (LOCAL_NETWORKS), plus this computer when `loopback`. An IPv4-mapped address is judged as the IPv4 it carries."""
    if "%" in address:
        raise HueError(SCOPED)      # an interface scope: the HTTP client cannot dial it
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        raise HueError("That is not an address this tool can reach.") from None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if ip.is_loopback:
        if loopback:
            return address
        raise HueError("That address is this computer itself, which this tool does not contact while it can be reached from your network.")
    if not any(ip in network for network in LOCAL_NETWORKS):
        raise HueError("This tool only contacts a bridge on your own network: that address is not a private or link-local one.")
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
    if "%" in host:
        raise HueError(SCOPED if ":" in host else "Type the address of the bridge, such as 10.0.0.5 or bridge.local.")
    if port is not None and not re.fullmatch(r"[0-9]{1,5}", port):
        raise HueError("Type the address of the bridge, such as 10.0.0.5 or bridge.local.")    # "bridge:abc": the port is not a number
    number = int(port) if port else DEFAULT_PORT
    if not host or not 1 <= number <= 65535:
        raise HueError("Type the address of the bridge, such as 10.0.0.5 or bridge.local.")
    return host, number


async def resolve(host: str, port: int) -> list[str]:
    infos = await asyncio.wait_for(asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM), RESOLVE_TIMEOUT)
    return list(dict.fromkeys(info[4][0] for info in infos))


async def target_address(host: str, port: int, loopback: bool = True) -> str:
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
        return check_address(host, loopback)
    try:
        addresses = await resolve(host, port)
    except (OSError, UnicodeError, asyncio.TimeoutError):    # a name such as "a..b" makes the resolver raise UnicodeError, which is not an OSError
        raise HueError("That name does not resolve. Try the bridge's IP address.") from None
    if not addresses:
        raise HueError("That name does not resolve. Try the bridge's IP address.")
    local = []
    for address in addresses:
        try:
            local.append(check_address(address, loopback))
        except HueError:
            continue
    if not local:
        check_address(addresses[0], loopback)     # raises with the plain "not on your own network" sentence
    return next((a for a in local if ":" not in a), local[0])


def _base(ip: str, port: int) -> str:
    return f"https://[{ip}]:{port}" if ":" in ip else f"https://{ip}:{port}"


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


async def probe(host_text: object, loopback: bool = True) -> Probe:
    """First contact: pin the certificate, read who the bridge says it is, and make sure the certificate agrees."""
    host, port = split_host(host_text)
    ip = await target_address(host, port, loopback)
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

def parse_service(record: dict, loopback: bool = True) -> dict | None:
    """One mDNS answer into {name, bridgeId, host}, or None when it offers no address on the local network."""
    props = {(k.decode("utf-8", "replace") if isinstance(k, bytes) else str(k)).lower(): v for k, v in (record.get("properties") or {}).items()}
    raw = props.get("bridgeid")
    raw = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else raw
    bridge_id = raw.upper() if isinstance(raw, str) and BRIDGE_ID_RE.match(raw) else None
    port = record.get("port") if isinstance(record.get("port"), int) else DEFAULT_PORT
    for address in sorted(record.get("addresses") or [], key=lambda a: ":" in a):   # IPv4 first
        try:
            check_address(address, loopback)
        except HueError:
            continue
        host = address if port == DEFAULT_PORT else (f"[{address}]:{port}" if ":" in address else f"{address}:{port}")
        name = _text(str(record.get("name") or "").removesuffix("." + SERVICE)) or "Hue Bridge"
        return {"name": name, "bridgeId": bridge_id, "host": host}
    return None


async def follow_up(names: set[str], request: Callable[[str, int], Awaitable[dict | None]], budget: float) -> list[dict]:
    """Ask for the details of at most MAX_ANNOUNCED of the announced names, together, and give up on the rest of the answers after `budget` seconds.

    What a network announces is not ours to bound, so the number of questions and the time they may take both are.
    """
    tasks = [asyncio.ensure_future(request(name, 2000)) for name in sorted(names)[:MAX_ANNOUNCED]]
    try:
        done, _pending = await asyncio.wait(tasks, timeout=max(budget, 0.0)) if tasks else (set(), set())
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
    return [task.result() for task in tasks if task in done and not task.cancelled() and task.exception() is None and task.result()]


async def browse_mdns(timeout: float) -> list[dict]:
    """Browse `_hue._tcp.local.` for `timeout` seconds, then follow up. Thin on purpose: parsing and filtering are in parse_service."""
    from zeroconf import ServiceStateChange
    from zeroconf.asyncio import AsyncServiceBrowser, AsyncServiceInfo, AsyncZeroconf

    started = asyncio.get_running_loop().time()
    azc, names = AsyncZeroconf(), set()

    def on_change(zeroconf, service_type, name, state_change) -> None:
        if state_change is not ServiceStateChange.Removed and len(names) < 1024:    # a bound on memory too, not only on questions
            names.add(name)

    async def ask(name: str, timeout_ms: int) -> dict | None:
        info = AsyncServiceInfo(SERVICE, name)
        if await info.async_request(azc.zeroconf, timeout_ms):
            return {"name": name, "addresses": info.parsed_addresses(), "port": info.port, "properties": dict(info.properties)}
        return None

    browser = AsyncServiceBrowser(azc.zeroconf, SERVICE, handlers=[on_change])
    try:
        await asyncio.sleep(timeout)
        left = DISCOVER_DEADLINE - 1.0 - (asyncio.get_running_loop().time() - started)    # a second kept back to close down before the hard deadline
        return await follow_up(names, ask, left)
    finally:
        await browser.async_cancel()
        await azc.async_close()


async def discover(loopback: bool = True) -> list[dict]:
    """The bridges answering on the network, only when the user asked. One overall deadline, whatever the network does."""
    try:
        records = await asyncio.wait_for(browse_mdns(DISCOVER_SECONDS), DISCOVER_DEADLINE)
    except (asyncio.TimeoutError, TimeoutError):
        raise HueError("The search of the network took too long and was stopped. Type the bridge's address instead.") from None
    except Exception:
        raise HueError("The search of the network could not run here.") from None
    found = {}
    for record in records:
        service = parse_service(record, loopback)
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

    def __init__(self, data_dir: Path | None, on_change: Notify | None = None, allow_loopback: bool = True) -> None:
        """data_dir None keeps everything in memory (demo mode). Loading the file contacts nothing.

        `allow_loopback` is whether this computer itself may be the bridge: true only where nobody signs in: a loopback bind with no
        password (`Access.local`). Otherwise a user signed in from the network, or through a proxy in front of a loopback bind, could use
        the bridge form to probe the server's own ports.
        The default keeps what the tests rely on: they run a fake bridge on loopback.
        """
        self.path = (data_dir / "hue.json") if data_dir else None
        self.on_change = on_change
        self.allow_loopback = allow_loopback
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
        self._search: asyncio.Task | None = None
        # The set-up in progress, if any: forgetting the bridge drops it, and every step of a set-up checks it is still the one.
        self._setup: object | None = None

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
    def _begin(self) -> object:
        """One set-up at a time. The token is what a step checks, after each wait, to know it was not cancelled meanwhile."""
        self._require_free()
        self.error = None
        token = self._setup = object()
        return token

    def _alive(self, token: object) -> None:
        if self._setup is not token:
            raise HueError("That set-up was cancelled.")

    def _release(self, token: object) -> None:
        """A set-up that failed or ended leaves the service free. A cancelled one has nothing to release: the service is not its any more."""
        if self._setup is token:
            self._setup, self.pairing = None, None

    async def start_pairing(self, host: object) -> dict:
        """Check the bridge, then ask it for a key every PAIR_INTERVAL until the link button is pressed or PAIR_TIMEOUT passes."""
        token = self._begin()
        self.pairing = "waiting"
        try:
            found = await probe(host, self.allow_loopback)
            self._alive(token)      # forgotten during the first contact: no pairing task may come out of it
            self._pair_task = asyncio.create_task(self._pair(found, str(host).strip(), token))
        except asyncio.CancelledError:
            self._release(token)
            raise
        except Exception as exc:    # whatever it is, the service must be free again and the user gets a sentence
            self._release(token)
            raise plain(exc) from None
        await self._changed()
        return self.status()

    async def set_key(self, host: object, key: object) -> dict:
        """An application key the user already has: checked against the bridge before it is kept."""
        token = self._begin()
        try:
            key = str(key or "").strip()
            if not KEY_RE.match(key):
                raise HueError("That does not look like an application key.")
            found = await probe(host, self.allow_loopback)
            self._alive(token)
            try:
                async with Link(found.ip, found.port, found.fingerprint, key) as link:
                    status, _data = await link.call("GET", "/clip/v2/resource/device")
            except Exception as exc:
                raise plain(exc) from None
            if status in (401, 403):
                raise HueError("The bridge did not accept that application key.")
            if status != 200:
                raise HueError("The bridge answered in a way this tool does not understand.")
            await self._adopt(found, str(host).strip(), key, token)
        except asyncio.CancelledError:
            self._release(token)
            raise
        except Exception as exc:
            self._release(token)
            raise plain(exc) from None
        return self.status()

    def _require_free(self) -> None:
        if self.config is not None:
            raise HueError("A bridge is already set up. Forget it first to set up another.")
        if self.pairing == "waiting":
            raise HueError("Pairing is under way. Press the link button on the bridge, or forget the bridge to cancel.")
        if self._setup is not None:
            raise HueError("A set-up is under way. Wait for it to end, or forget the bridge to cancel it.")

    async def _pair(self, found: Probe, host: str, token: object) -> None:
        deadline = time.monotonic() + PAIR_TIMEOUT
        try:
            async with Link(found.ip, found.port, found.fingerprint) as link:
                while True:
                    _status, data = await link.call("POST", "/api", {"devicetype": DEVICE_TYPE})
                    self._alive(token)
                    item = data[0] if isinstance(data, list) and data and isinstance(data[0], dict) else {}
                    success = item.get("success") if isinstance(item.get("success"), dict) else None
                    error = item.get("error") if isinstance(item.get("error"), dict) else None
                    if success and isinstance(success.get("username"), str) and KEY_RE.match(success["username"]):
                        key = success["username"]
                        break
                    if not error or error.get("type") != 101:
                        raise HueError("The bridge refused the pairing request." if error else "That does not look like a Hue bridge.")
                    if time.monotonic() >= deadline:
                        self.pairing, self._setup = "timeout", None
                        await self._changed()
                        return
                    await asyncio.sleep(PAIR_INTERVAL)
            await self._adopt(found, host, key, token)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            if self._setup is token:    # a cancelled set-up says nothing: its bridge is not the user's concern any more
                self.pairing, self.error, self._setup = None, str(plain(exc)), None
                await self._changed()

    async def _adopt(self, found: Probe, host: str, key: str, token: object) -> None:
        config = {"host": host, "bridge_id": found.bridge_id, "name": found.name, "key": key, "fingerprint": found.fingerprint, "added": int(time.time())}
        self._alive(token)
        self._save(config)      # first: a bridge that could not be written down is not adopted, not even for this session
        self.config = config    # (no wait between the check above and here)
        self.error, self.devices, self.channel, self.last_read = None, {}, None, None
        await self.refresh()
        if self._setup is token:
            if self.pairing is not None:    # pairing is over only once the bridge was read: no "set up, never read" in between
                self.pairing = None
                await self._changed()
            self._setup = None
        self.start(read_now=False)      # just read: the next one is due in REFRESH_SECONDS

    def _save(self, config: dict) -> None:
        """Write the file owner-only from the first byte, flushed to disk before it replaces the old one. A failure is a plain sentence."""
        if not self.path:
            return
        tmp = self.path.with_suffix(".json.tmp")
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp.unlink(missing_ok=True)
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)    # owner only from the first byte, not after the fact
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(json.dumps(config, indent=2) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, self.path)
        except OSError:
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                pass
            raise HueError("The bridge could not be saved on this computer, so it was not set up. Check that the data folder can be written to.") from None

    async def search(self) -> list[dict]:
        """Look for bridges, one search at a time: a request made meanwhile gets the running search's result."""
        task = self._search
        if task is None or task.done():
            task = self._search = asyncio.create_task(discover(self.allow_loopback))
            task.add_done_callback(lambda t: t.cancelled() or t.exception())    # an error nobody was left to read is not an unhandled one
        return await asyncio.shield(task)

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
                ip = await target_address(host, port, self.allow_loopback)      # looked up and checked again each time
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
        """Drop the bridge: key, certificate, names, and any set-up under way, including one still in its first contact."""
        self._setup = None      # first, with no wait before it: a set-up that wakes up from now on finds it was cancelled
        await self._cancel()
        self.config, self.devices, self.channel, self.last_read, self.error, self.pairing = None, {}, None, None, None, None
        if self.path:
            self.path.unlink(missing_ok=True)
        await self._changed()
        return self.status()

    async def stop(self) -> None:
        self._setup = None
        if self._search is not None and not self._search.done():
            self._search.cancel()
            await asyncio.gather(self._search, return_exceptions=True)
        await self._cancel()
