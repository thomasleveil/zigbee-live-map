"""Web server: frames in, events out over a WebSocket, pages to draw and manage them.

The pages carry secrets (network keys, the live traffic), so every request is sorted into exactly one of
three access channels, decided in one place (`access.Access.channel`) from how the server was started and
from the address of the TCP connection, never from a header:

- local: the server was started on a loopback address (the default, 127.0.0.1). A web site you visit must
  not be able to use your browser to read your radio traffic or edit your device lists. Three rules do that:
  every request must be addressed to the local host name, which stops DNS rebinding; plain reads (GET) are
  answered without any cross-origin permission, so the browser itself keeps another site from seeing the
  answer; the live connection and every change must carry a token that is drawn at start-up and handed out
  by a plain read, which therefore only this tool's own page can obtain. The Origin header is not compared
  to an exact value: browsers and extensions rewrite it in ways that cannot be predicted (some drop the
  port). When present it must still name the local host.
- ingress: started with --ingress, and the peer is the Home Assistant supervisor (172.30.32.2), the only
  address Home Assistant's ingress proxy connects from. Home Assistant has already signed the user in, so
  there is no login, and Host and Origin are not checked (behind the proxy they are Home Assistant's). The
  token is still required for every change and for /ws.
- lan: every other request on a non-loopback bind, loopback peers included. The Host must be the address of
  the socket the request arrived on, or an --allowed-host name; every route needs a signed-in session
  (a random cookie kept in memory) except the login page, its POST, the static files and the locale files;
  changes and /ws also need the token, and an Origin, when present, must name an allowed host. Without a
  password (--ingress alone) nobody can sign in, so every lan request is refused.

Outside the ingress channel the pages cannot be framed by another site. The pages use relative URLs only,
so they work at "/" and under any path prefix a reverse proxy puts in front of them.
"""

from __future__ import annotations

import asyncio
import hmac
import json
import math
import re
import secrets
import sys
import threading
import time
from collections import deque
from importlib import resources
from pathlib import Path
from urllib.parse import urlsplit

from aiohttp import WSMsgType, web

from . import __version__, access as accessmod, crypto, decode, demo, keys as keystore
from .access import COOKIE, INGRESS, LAN, LOCAL, Access, LoginGuard, Sessions
from .devices import DeviceError, DeviceStore
from .frames import Classifier, read_pcap
from .hue import HueService
from .keys import KeyStore
from .vendors import Registry, VendorError

STATIC_TYPES = {".html": "text/html", ".css": "text/css", ".js": "text/javascript", ".json": "application/json"}
STATIC_NAME = re.compile(r"^[a-z0-9_-]+\.(css|js)$")
LOCALE_CODE = re.compile(r"^[a-zA-Z]{2,3}(-[a-zA-Z0-9]{2,8})?$")
PAGES = {"/": "index.html", "/devices": "devices.html"}   # what an unauthenticated visitor is sent to the login for
FRAME_HEADERS = {"X-Frame-Options": "DENY", "Content-Security-Policy": "frame-ancestors 'none'"}


def _static(name: str) -> str:
    return resources.files("zigbee_live_map").joinpath("static", name).read_text(encoding="utf-8")


def list_locales() -> list[dict]:
    found = []
    for entry in resources.files("zigbee_live_map").joinpath("static", "locales").iterdir():
        code = entry.name.removesuffix(".json")
        if entry.name.endswith(".json") and LOCALE_CODE.match(code):
            try:
                found.append({"code": code, "name": json.loads(entry.read_text(encoding="utf-8")).get("_name", code)})
            except ValueError:
                continue
    return sorted(found, key=lambda item: item["code"])


class Hub:
    """Keeps the recent events and fans every new one out to the connected pages."""

    def __init__(self, store: DeviceStore, registry: Registry, info: dict, backlog: int, keys: KeyStore | None = None,
                 hue: HueService | None = None) -> None:
        self.store, self.registry, self.info = store, registry, info
        self.keys = keys if keys is not None else KeyStore(None)
        self.hue = hue if hue is not None else HueService(None)   # memory only, and silent until the user sets a bridge up
        self.hue.on_change = self.hue_changed
        self.status = {"type": "status", "sniffer": "starting", "detail": ""}
        self.events: deque = deque(maxlen=backlog)
        self.clients: set[web.WebSocketResponse] = set()
        self.classifier = Classifier()
        self._names_sent: str | None = None   # what the pages were last sent as `names` and as `hue` (as JSON, to compare): a read that
        self._hue_sent: str | None = None     # found nothing new wakes nobody
        self.heard: dict[str, str] = {}  # IEEE -> short address, as heard on the air
        self.generation = 0  # bumped on every channel change, so frames from the old channel are dropped
        self.source: LiveSource | None = None
        # Security: what this network's own traffic reveals once a key is known or recovered.
        self.network_key: bytes | None = None   # held in memory only, never written to disk
        self.key_source: str | None = None       # "recovered" (from a default-key join) or "entered"
        self.vulnerable = False                   # a join was secured with the default link key
        self.secure_join_seen = False             # a join was secured with a non-default link key
        self.identities: dict[str, dict] = {}     # NWK short address -> {manufacturer, model, power}
        self.link_quality: dict[str, list] = {}   # router NWK short address -> per-neighbour costs
        self.batteries: dict[str, dict] = {}      # NWK short address -> {percent} or {volts}
        self.pan: str | None = None               # the dominant PAN heard, used to pick a saved key
        self._pan_counts: dict[str, int] = {}

    def names(self) -> dict[str, dict]:
        """What the pages call a device: the user's lists first, the bridge's own name for any device no list names.

        Field by field: a list entry that has no name (only a model or a short address, which import allows) keeps its other fields
        and takes the bridge's name. Computed on the way out and written nowhere: the lists stay exactly what the user made them.
        """
        names = self.hue.fallback_names()
        for ieee, entry in self.store.merged().items():
            merged = dict(entry)
            if not merged.get("name") and ieee in names:
                merged["name"] = names[ieee]["name"]
            names[ieee] = merged
        return names

    def vendors(self) -> dict[str, str]:
        known = set(self.store.merged()) | set(self.heard)
        return {ieee: org for ieee in known if (org := self.registry.lookup(ieee))}

    def identified(self) -> dict[str, dict]:
        """Heard devices whose identity was decrypted, by IEEE: what a list can be filled from."""
        return {ieee: {"nwk": short, **self.identities[short]} for ieee, short in self.heard.items() if short in self.identities}

    def security_state(self) -> dict:
        return {"vulnerable": self.vulnerable, "secureJoinSeen": self.secure_join_seen,
                "keyKnown": self.network_key is not None, "keySource": self.key_source,
                "key": self.network_key.hex() if self.network_key else None, "pan": self.pan}

    async def _apply_saved_key(self) -> None:
        """When the live PAN has a key saved from a previous session, decrypt with it automatically."""
        saved = self.keys.get(self.pan)
        if saved and saved != self.network_key and self.key_source in (None, "saved"):
            self.network_key, self.key_source = saved, "saved"
            self.identities.clear()
            self.link_quality.clear()
            self.batteries.clear()
            await self.send_security()

    async def send_security(self) -> None:
        await self.send_all({"type": "security", **self.security_state()})

    def hello(self) -> dict:
        return {"type": "hello", "version": __version__, **self.info, "names": self.names(), "hue": self.hue.view(),
                "vendors": self.vendors(), "security": self.security_state(),
                "identities": self.identities, "linkCosts": self.link_quality, "batteries": self.batteries}

    async def send_all(self, message: dict) -> None:
        text = json.dumps(message, separators=(",", ":"))
        for ws in list(self.clients):
            try:
                await ws.send_str(text)
            except (ConnectionError, RuntimeError):
                self.clients.discard(ws)

    async def publish(self, frame: bytes, ts: float, rssi: int | None) -> None:
        event = self.classifier.event(frame, ts, rssi)
        self.events.append(event)
        pan = event.get("pan")
        if pan and pan != "0xffff":
            self._pan_counts[pan] = self._pan_counts.get(pan, 0) + 1
            if pan != self.pan and self._pan_counts[pan] >= self._pan_counts.get(self.pan, 0):
                self.pan = pan
                await self._apply_saved_key()
        ieee, short = event.get("ieee"), event.get("ms")
        if ieee and short and self.heard.get(ieee) != short:
            self.heard[ieee] = short
            org = self.registry.lookup(ieee)
            if org:
                await self.send_all({"type": "vendors", "vendors": {ieee: org}})
        await self._inspect(frame, event)
        await self.send_all({"type": "ev", "e": event})

    async def _inspect(self, frame: bytes, event: dict) -> None:
        """Read what the encrypted layers give up: the vulnerability test, device identity, link costs."""
        if not self.vulnerable:
            recovered = decode.recover_network_key(frame)   # default link key only: that is the test
            if recovered is not None:
                self.vulnerable = True
                if self.network_key is None:
                    self.network_key, self.key_source = recovered, "recovered"
                await self.send_security()
            elif not self.secure_join_seen and decode.transport_key_envelope(frame) is not None:
                self.secure_join_seen = True   # a join, but secured with a key that is not the default one
                await self.send_security()
        key = self.network_key
        if key is None:
            return
        ns = event.get("ns")
        if not ns:
            return
        if event.get("cat") == "link_status":
            rows = decode.link_costs(frame, key)
            if rows is not None and self.link_quality.get(ns) != rows:
                self.link_quality[ns] = rows
                await self.send_all({"type": "linkcosts", "addr": ns, "rows": rows})
        elif event.get("cat", "").startswith("data"):
            info = decode.read_device(frame, key)   # one decrypt for both identity and battery
            if info:
                batt = info["battery"]
                if batt is not None and self.batteries.get(ns) != batt:
                    self.batteries[ns] = batt
                    await self.send_all({"type": "battery", "addr": ns, "batt": batt})
                if info["identity"] is not None and ns not in self.identities:
                    self.identities[ns] = info["identity"]
                    await self.send_all({"type": "identity", "addr": ns, "id": info["identity"]})

    async def set_status(self, sniffer: str, detail: str = "") -> None:
        self.status = {"type": "status", "sniffer": sniffer, "detail": detail}
        await self.send_all(self.status)

    async def names_changed(self) -> None:
        names = self.names()
        self._names_sent = json.dumps(names, sort_keys=True)
        await self.send_all({"type": "names", "names": names, "vendors": self.vendors()})

    async def hue_changed(self) -> None:
        """The bridge was read, set up or forgotten: the pages get the new names, then what the hub says about each device.

        Only what differs from the last time: the periodic read tells nobody that nothing happened. The time of the last read does
        not count (pages learn it with their next status request or change).
        """
        if json.dumps(self.names(), sort_keys=True) != self._names_sent:
            await self.names_changed()
        view = self.hue.view()
        stamp = json.dumps({key: value for key, value in view.items() if key != "lastRead"}, sort_keys=True)
        if stamp != self._hue_sent:
            self._hue_sent = stamp
            await self.send_all({"type": "hue", **view})

    async def tune(self, channel: int) -> None:
        if self.source is None or channel not in range(11, 27) or channel == self.info["channel"]:
            return
        self.generation += 1
        self.info["channel"] = channel
        self.events.clear()
        self.heard.clear()
        self.classifier = Classifier()
        # A new channel is a new network: drop the per-network verdict, key and PAN; a saved key re-applies per PAN.
        self.vulnerable = self.secure_join_seen = False
        self.identities.clear()
        self.link_quality.clear()
        self.batteries.clear()
        self.pan = None
        self._pan_counts.clear()
        self.network_key = self.key_source = None
        self.source.set_channel(channel, self.generation)
        await self.send_all(self.hello())
        await self.set_status("starting")


class LiveSource:
    """Blocking USB reads live in a thread; everything else happens on the event loop."""

    def __init__(self, loop: asyncio.AbstractEventLoop, queue: asyncio.Queue, channel: int, pcap_path: str | None) -> None:
        self.loop, self.queue, self.pcap_path = loop, queue, pcap_path
        self.channel, self.generation = channel, 0
        self._stop, self._retune = threading.Event(), threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True)

    def set_channel(self, channel: int, generation: int) -> None:
        self.channel, self.generation = channel, generation
        self._retune.set()

    def stop(self) -> None:
        self._stop.set()
        self._retune.set()
        self.thread.join(timeout=2)

    def _post(self, *item) -> None:
        self.loop.call_soon_threadsafe(self.queue.put_nowait, item)

    def _run(self) -> None:
        import usb.core

        from . import sniffer

        pcap = open(self.pcap_path, "wb") if self.pcap_path else None
        if pcap:
            pcap.write(sniffer.pcap_header())
            pcap.flush()
        try:
            while not self._stop.is_set():
                self._retune.clear()
                channel, generation, dev = self.channel, self.generation, None
                try:
                    dev = sniffer.open_sniffer(channel)
                    self._post("status", generation, "ok", "")
                    buf = b""
                    while not self._retune.is_set():
                        buf += sniffer.read_chunk(dev)
                        found, buf = sniffer.extract_frames(buf)
                        for frame, rssi, crc_ok in found:
                            if not crc_ok:
                                continue
                            now = time.time()
                            if pcap:
                                pcap.write(sniffer.pcap_record(now, frame))
                                pcap.flush()   # so the capture is readable while the tool is still running
                            self._post("frame", generation, now, frame, rssi)
                except (sniffer.SnifferError, usb.core.USBError) as exc:
                    self._post("status", generation, "absent", str(exc))
                    self._retune.wait(2)
                finally:
                    if dev is not None:
                        sniffer.close_sniffer(dev)
        finally:
            if pcap:
                pcap.close()


async def replay_source(queue: asyncio.Queue, path: str, speed: float) -> None:
    """Loop over a capture, keeping the gaps between frames, stamped with the current time."""
    while True:
        await queue.put(("status", 0, "replay", Path(path).name))
        previous = None
        for ts, frame in read_pcap(path):
            if previous is not None:
                await asyncio.sleep(min(max(ts - previous, 0) / speed, 5))
            previous = ts
            await queue.put(("frame", 0, time.time(), frame, None))
        await asyncio.sleep(2)


async def demo_source(queue: asyncio.Queue, speed: float) -> None:
    await queue.put(("status", 0, "demo", ""))

    async def emit(frame: bytes, rssi: int) -> None:
        await queue.put(("frame", 0, time.time(), frame, rssi))

    await demo.DemoNetwork(emit, speed).run()


async def pump(queue: asyncio.Queue, hub: Hub) -> None:
    while True:
        kind, generation, *rest = await queue.get()
        if generation != hub.generation:
            continue
        if kind == "status":
            await hub.set_status(*rest)
        else:
            ts, frame, rssi = rest
            await hub.publish(frame, ts, rssi)


# ------------------------------------------------------------------------------------------ HTTP

HUB = web.AppKey("hub", Hub)
TOKEN = web.AppKey("token", str)
ACCESS = web.AppKey("access", Access)
SESSIONS = web.AppKey("sessions", Sessions)
GUARD = web.AppKey("login_guard", LoginGuard)
CHANNEL = web.RequestKey("channel", str)   # which access channel this request fell into
LOCAL_NAMES = {"127.0.0.1", "localhost"}
GATE_TEXT = "zigbee-live-map refused this request: {}."


def _peer(request: web.Request) -> str | None:
    """The address of the TCP connection. Never a header: any client can write those."""
    peer = request.transport.get_extra_info("peername") if request.transport else None
    return peer[0] if peer else None


def _socket(request: web.Request) -> tuple[str, int]:
    """The address and port of the socket the request arrived on."""
    name = request.transport.get_extra_info("sockname")
    return name[0], name[1]


def _guarded(request: web.Request) -> bool:
    """A change, or the live connection: what needs the token."""
    return request.method not in ("GET", "HEAD") or request.path == "/ws"


def _token_ok(request: web.Request) -> bool:
    token = request.headers.get("X-ZLM-Token") or request.query.get("token") or ""
    return hmac.compare_digest(token, request.app[TOKEN])


def _refuse(request: web.Request, reason: str) -> web.HTTPForbidden:
    print(f"refused {request.method} {request.path}: {reason} (Host: {request.host}, Origin: {request.headers.get('Origin')})", file=sys.stderr, flush=True)
    return web.HTTPForbidden(text=GATE_TEXT.format(reason))


def _unauthorized(request: web.Request) -> web.HTTPException:
    """Not signed in: a page goes to the login (a relative URL, so it holds under any path prefix), anything else is told 401."""
    if request.method in ("GET", "HEAD") and request.path in PAGES:
        return web.HTTPFound("login", headers={"Cache-Control": "no-store"})
    return web.HTTPUnauthorized(text=json.dumps({"error": "sign in required"}), content_type="application/json", headers={"Cache-Control": "no-store"})


# One function per channel holds that channel's rules. Each returns the refusal to raise, or None to let the request through.

def local_rules(request: web.Request) -> web.HTTPException | None:
    sock_ip, port = _socket(request)   # the port we really listen on
    mine = accessmod.ip_of(sock_ip)
    # On the default bind these are exactly 127.0.0.1 and localhost; a bind on ::1 or 127.0.0.2 adds its own address, so it can be reached at all.
    names = LOCAL_NAMES | ({accessmod.literal(mine).strip("[]")} if mine else set())
    hosts = {f"127.0.0.1:{port}", f"localhost:{port}"} | ({f"{accessmod.literal(mine)}:{port}"} if mine else set())
    origin = request.headers.get("Origin")
    guarded = _guarded(request)
    reason = None
    if request.host not in hosts:
        reason = "it is not addressed to this local server"
    elif guarded and origin is not None and urlsplit(origin).hostname not in names:
        reason = "it comes from another site"
    elif guarded and not _token_ok(request):
        reason = "it does not carry this session's token (reload the page)"
    return _refuse(request, reason) if reason else None


def ingress_rules(request: web.Request) -> web.HTTPException | None:
    """Home Assistant signed the user in and proxies for them: no login, and Host and Origin are its own. The token still guards changes."""
    if _guarded(request) and not _token_ok(request):
        return _refuse(request, "it does not carry this session's token (reload the page)")
    return None


def lan_rules(request: web.Request) -> web.HTTPException | None:
    access, sessions = request.app[ACCESS], request.app[SESSIONS]
    sock_ip, port = _socket(request)
    origin = request.headers.get("Origin")
    if not access.host_ok(request.host, sock_ip, port):   # first: before a login, a redirect or a 401 can teach a rebinding page anything
        return _refuse(request, "it is not addressed to a host this server accepts")
    if access.password is None:   # --ingress alone: only the supervisor may use the tool
        return _refuse(request, "this server answers only Home Assistant")
    if request.method == "POST" and request.path == "/login":   # no session yet, no token yet: but not from another site
        if origin is not None and not access.origin_ok(origin, sock_ip):
            return _refuse(request, "it comes from another site")
        return None
    path = request.path
    if request.method in ("GET", "HEAD") and (path in ("/login", "/locales") or path.startswith(("/static/", "/locales/"))):
        return None
    if not sessions.valid(request.cookies.get(COOKIE)):
        return _unauthorized(request)
    if _guarded(request):
        if origin is not None and not access.origin_ok(origin, sock_ip):
            return _refuse(request, "it comes from another site")
        if not _token_ok(request):
            return _refuse(request, "it does not carry this session's token (reload the page)")
    return None


CHANNEL_RULES = {LOCAL: local_rules, INGRESS: ingress_rules, LAN: lan_rules}


@web.middleware
async def access_control(request: web.Request, handler):
    channel = request.app[ACCESS].channel(_peer(request))   # the one place the channel is decided
    request[CHANNEL] = channel
    refusal = CHANNEL_RULES[channel](request)
    if refusal is not None:
        raise refusal
    try:
        return await handler(request)
    except (DeviceError, VendorError) as exc:
        return web.json_response({"error": str(exc)}, status=400)


async def _response_headers(request: web.Request, response: web.StreamResponse) -> None:
    """On every response, refusals and redirects included: only Home Assistant may show the pages in a frame, and the lan's answers are never cached."""
    channel = request.get(CHANNEL)
    if channel != INGRESS:
        response.headers.update(FRAME_HEADERS)
    if channel == LAN:
        response.headers.setdefault("Cache-Control", "no-store")


def _text(body: str, kind: str, status: int = 200) -> web.Response:
    return web.Response(text=body, content_type=STATIC_TYPES[kind], charset="utf-8", status=status, headers={"Cache-Control": "no-store"})


async def handle_page(request: web.Request) -> web.Response:
    return _text(_static(PAGES[request.path]), ".html")


def _login_page(failed: bool = False, status: int = 200) -> web.Response:
    """The login page. A failed attempt gets the same page with its one message shown, so it also works without JavaScript."""
    body = _static("login.html")
    if failed:
        body = body.replace('data-state="idle"', 'data-state="failed"').replace('aria-invalid="false"', 'aria-invalid="true"')
    return _text(body, ".html", status)


async def handle_login_page(request: web.Request) -> web.Response:
    if request[CHANNEL] != LAN:
        raise web.HTTPNotFound()   # nothing to sign in to here
    if request.app[SESSIONS].valid(request.cookies.get(COOKIE)):
        raise web.HTTPFound("./")
    return _login_page()


async def handle_login(request: web.Request) -> web.Response:
    if request[CHANNEL] != LAN:
        raise web.HTTPNotFound()
    access, sessions, guard = request.app[ACCESS], request.app[SESSIONS], request.app[GUARD]
    peer = _peer(request) or ""
    try:   # the body first: from the gate to the verdict there must be no await, or attempts started together would all pass the gate
        given = (await request.post()).get("password")
    except (ValueError, UnicodeError):
        given = None
    wait = guard.wait(peer)
    if wait > 0:   # too soon after failures: refused without looking at the password, so the refusal cannot tell a right guess from a wrong one
        page = _login_page(failed=True, status=429)
        page.headers["Retry-After"] = str(math.ceil(wait))
        return page
    if not isinstance(given, str) or not access.password_ok(given):
        guard.failed(peer)
        return _login_page(failed=True, status=401)
    guard.succeeded(peer)
    response = web.Response(status=303, headers={"Location": "./", "Cache-Control": "no-store"})
    response.set_cookie(COOKIE, sessions.start(), max_age=accessmod.SESSION_TTL, path="/", httponly=True, samesite="Strict",
                        secure=request.headers.get("X-Forwarded-Proto") == "https")   # behind a TLS proxy the browser must not send it in clear
    return response


async def handle_logout(request: web.Request) -> web.Response:
    request.app[SESSIONS].end(request.cookies.get(COOKIE))
    response = web.json_response({})
    response.del_cookie(COOKIE, path="/")
    return response


async def handle_static(request: web.Request) -> web.Response:
    name = request.match_info["name"]
    if not STATIC_NAME.match(name):
        raise web.HTTPNotFound()
    try:
        return _text(_static(name), "." + name.rsplit(".", 1)[1])
    except (FileNotFoundError, OSError):
        raise web.HTTPNotFound() from None


async def handle_locales(_request: web.Request) -> web.Response:
    return web.json_response(list_locales(), headers={"Cache-Control": "no-store"})


async def handle_locale(request: web.Request) -> web.Response:
    code = request.match_info["code"]
    if not LOCALE_CODE.match(code):
        raise web.HTTPNotFound()
    try:
        return _text(_static(f"locales/{code}.json"), ".json")
    except (FileNotFoundError, OSError):
        raise web.HTTPNotFound() from None


async def _json(request: web.Request) -> dict:
    try:
        data = await request.json()
    except ValueError:
        raise DeviceError("the request body is not JSON") from None
    if not isinstance(data, dict):
        raise DeviceError("the request body must be a JSON object")
    return data


async def api_lists(request: web.Request) -> web.Response:
    hub: Hub = request.app[HUB]
    named = set(hub.store.merged())
    heard = [{"ieee": ieee, "nwk": short} for ieee, short in sorted(hub.heard.items()) if ieee not in named]
    identified = hub.identified()
    fillable = len(identified.keys() - hub.store.known())   # the page explains an empty fill from these three
    return web.json_response({"lists": hub.store.describe(), "heard": heard, "vendors": hub.vendors(), "persistent": hub.store.dir is not None,
                              "keyKnown": hub.network_key is not None, "identified": len(identified), "fillable": fillable})


async def api_list_create(request: web.Request) -> web.Response:
    hub: Hub = request.app[HUB]
    list_id = hub.store.create((await _json(request)).get("name", ""))
    await hub.names_changed()
    return web.json_response({"id": list_id})


async def api_list_update(request: web.Request) -> web.Response:
    hub: Hub = request.app[HUB]
    data = await _json(request)
    hub.store.update(request.match_info["list"], name=data.get("name"), enabled=data.get("enabled"))
    await hub.names_changed()
    return web.json_response({})


async def api_list_delete(request: web.Request) -> web.Response:
    hub: Hub = request.app[HUB]
    hub.store.delete(request.match_info["list"])
    await hub.names_changed()
    return web.json_response({})


async def api_device_set(request: web.Request) -> web.Response:
    hub: Hub = request.app[HUB]
    hub.store.set_device(request.match_info["list"], request.match_info["ieee"], await _json(request))
    await hub.names_changed()
    return web.json_response({})


async def api_device_delete(request: web.Request) -> web.Response:
    hub: Hub = request.app[HUB]
    hub.store.delete_device(request.match_info["list"], request.match_info["ieee"])
    await hub.names_changed()
    return web.json_response({})


async def api_fill(request: web.Request) -> web.Response:
    hub: Hub = request.app[HUB]
    added = hub.store.fill_from_identities(request.match_info["list"], hub.identified())
    if added:
        await hub.names_changed()
    return web.json_response({"added": added})


async def api_import(request: web.Request) -> web.Response:
    hub: Hub = request.app[HUB]
    count = hub.store.import_text(request.match_info["list"], await request.text())
    await hub.names_changed()
    return web.json_response({"imported": count})


async def api_export(request: web.Request) -> web.Response:
    hub: Hub = request.app[HUB]
    name, kind, text = hub.store.export(request.match_info["list"], request.query.get("format", "json"))
    return web.Response(text=text, content_type=kind, charset="utf-8", headers={"Content-Disposition": f'attachment; filename="{name}"'})


async def api_session(request: web.Request) -> web.Response:
    return web.json_response({"token": request.app[TOKEN], "signOut": request[CHANNEL] == LAN}, headers={"Cache-Control": "no-store"})


async def api_keys(request: web.Request) -> web.Response:
    hub: Hub = request.app[HUB]
    return web.json_response({"keys": hub.keys.describe(), "pan": hub.pan})


async def api_keys_set(request: web.Request) -> web.Response:
    hub: Hub = request.app[HUB]
    data = await _json(request)
    key = keystore.normalise_key(data.get("key", ""))
    name = crypto.link_key_name(key)
    if name:
        raise DeviceError(f"that is {name}, a link key, not a network key")
    pan = hub.keys.set(request.match_info["pan"], key.hex(), data.get("label", ""))
    if pan == (hub.pan or ""):   # a key for the network on the air now: start decrypting with it
        hub.network_key, hub.key_source = key, "saved"
        hub.identities.clear()
        hub.link_quality.clear()
        hub.batteries.clear()
        await hub.send_security()
    return web.json_response({"keys": hub.keys.describe(), "pan": hub.pan, "security": hub.security_state()})


async def api_keys_delete(request: web.Request) -> web.Response:
    hub: Hub = request.app[HUB]
    pan = keystore.normalise_pan(request.match_info["pan"])
    hub.keys.delete(pan)
    if pan == (hub.pan or "") and hub.key_source == "saved":
        hub.network_key = hub.key_source = None
        hub.identities.clear()
        hub.link_quality.clear()
        hub.batteries.clear()
        await hub.send_security()
    return web.json_response({"keys": hub.keys.describe(), "pan": hub.pan, "security": hub.security_state()})


# The Hue Bridge. Everything that causes a network call is a guarded change (POST/DELETE), never a plain read:
# a plain read is open to any page in the browser, so it must not be able to make this tool dial anything.

async def api_hue(request: web.Request) -> web.Response:
    return web.json_response(request.app[HUB].hue.status())


async def api_hue_discover(request: web.Request) -> web.Response:
    return web.json_response({"bridges": await request.app[HUB].hue.search()})


async def api_hue_pair(request: web.Request) -> web.Response:
    return web.json_response(await request.app[HUB].hue.start_pairing((await _json(request)).get("host")))


async def api_hue_key(request: web.Request) -> web.Response:
    data = await _json(request)
    return web.json_response(await request.app[HUB].hue.set_key(data.get("host"), data.get("key")))


async def api_hue_refresh(request: web.Request) -> web.Response:
    hub: Hub = request.app[HUB]
    await hub.hue.refresh()
    return web.json_response(hub.hue.status())


async def api_hue_forget(request: web.Request) -> web.Response:
    return web.json_response(await request.app[HUB].hue.forget())


async def api_vendors(request: web.Request) -> web.Response:
    return web.json_response(request.app[HUB].registry.meta)


async def api_vendors_refresh(request: web.Request) -> web.Response:
    hub: Hub = request.app[HUB]
    meta = await asyncio.get_running_loop().run_in_executor(None, hub.registry.refresh)
    await hub.names_changed()
    return web.json_response(meta)


async def handle_ws(request: web.Request) -> web.StreamResponse:
    hub: Hub = request.app[HUB]
    ws = web.WebSocketResponse(heartbeat=20)
    await ws.prepare(request)
    await ws.send_json(hub.hello())
    await ws.send_json(hub.status)
    await ws.send_str(json.dumps({"type": "backlog", "events": list(hub.events)}, separators=(",", ":")))
    hub.clients.add(ws)
    try:
        async for msg in ws:
            if msg.type != WSMsgType.TEXT:
                continue
            try:
                data = json.loads(msg.data)
            except ValueError:
                continue
            if not isinstance(data, dict):
                continue
            if data.get("type") == "rename":
                hub.store.rename(str(data.get("ieee", "")), str(data.get("name", "")))
                await hub.names_changed()
            elif data.get("type") == "channel" and isinstance(data.get("channel"), int):
                await hub.tune(data["channel"])
    finally:
        hub.clients.discard(ws)
    return ws


def build_app(hub: Hub, access: Access | None = None, clock=time.monotonic) -> web.Application:
    """With no `access` the server is what it always was: loopback only."""
    app = web.Application(middlewares=[access_control], client_max_size=2 * 1024 * 1024)
    app[HUB] = hub
    app[TOKEN] = secrets.token_urlsafe(24)
    app[ACCESS] = access if access is not None else Access()
    app[SESSIONS] = Sessions(clock)
    app[GUARD] = LoginGuard(clock)
    app.on_response_prepare.append(_response_headers)
    app.add_routes([
        web.get("/", handle_page), web.get("/devices", handle_page), web.get("/ws", handle_ws),
        web.get("/login", handle_login_page), web.post("/login", handle_login), web.post("/logout", handle_logout),
        web.get("/static/{name}", handle_static), web.get("/locales", handle_locales), web.get("/locales/{code}.json", handle_locale),
        web.get("/api/lists", api_lists), web.post("/api/lists", api_list_create),
        web.patch("/api/lists/{list}", api_list_update), web.delete("/api/lists/{list}", api_list_delete),
        web.put("/api/lists/{list}/devices/{ieee}", api_device_set), web.delete("/api/lists/{list}/devices/{ieee}", api_device_delete),
        web.post("/api/lists/{list}/fill-identities", api_fill), web.post("/api/lists/{list}/import", api_import), web.get("/api/lists/{list}/export", api_export),
        web.get("/api/session", api_session), web.get("/api/vendors", api_vendors), web.post("/api/vendors/refresh", api_vendors_refresh),
        web.get("/api/keys", api_keys), web.put("/api/keys/{pan}", api_keys_set), web.delete("/api/keys/{pan}", api_keys_delete),
        web.get("/api/hue", api_hue), web.delete("/api/hue", api_hue_forget), web.post("/api/hue/discover", api_hue_discover),
        web.post("/api/hue/pair", api_hue_pair), web.post("/api/hue/key", api_hue_key), web.post("/api/hue/refresh", api_hue_refresh),
    ])
    app.on_cleanup.append(lambda _app: hub.hue.stop())
    return app


def demo_store() -> DeviceStore:
    store = DeviceStore(None)
    store.lists["demo"] = {"name": "Demo network", "enabled": True, "devices": demo.names()}
    return store


async def serve(args, access: Access | None = None) -> None:
    access = access if access is not None else accessmod.from_args(args)
    mode = "demo" if args.demo else "replay" if args.replay else "live"
    data_dir = Path(args.data_dir).expanduser()
    store = demo_store() if mode == "demo" else DeviceStore(data_dir)
    info = {"channel": args.channel if mode == "live" else None, "mode": mode, "focus": args.focus, "can_tune": mode == "live"}
    hub = Hub(store, Registry(data_dir), info, args.backlog, keys=KeyStore(None if mode == "demo" else data_dir),
              hue=HueService(None if mode == "demo" else data_dir, allow_loopback=access.loopback))
    hub.hue.start()   # only reads a bridge the user set up in an earlier session; nothing at all otherwise
    queue: asyncio.Queue = asyncio.Queue()
    tasks = [asyncio.create_task(pump(queue, hub))]
    if mode == "demo":
        tasks.append(asyncio.create_task(demo_source(queue, args.speed)))
    elif mode == "replay":
        tasks.append(asyncio.create_task(replay_source(queue, args.replay, args.speed)))
    else:
        hub.source = LiveSource(asyncio.get_running_loop(), queue, args.channel, args.pcap)
        hub.source.thread.start()

    runner = web.AppRunner(build_app(hub, access))
    await runner.setup()
    await web.TCPSite(runner, access.host, args.port).start()
    port = runner.addresses[0][1]   # what the system gave, when the port asked for was 0
    url = access.url(port)
    print(f"zigbee-live-map {__version__}: {url}  ({mode}{f', channel {args.channel}' if mode == 'live' else ''})", flush=True)
    if not access.loopback:
        print(f"  reachable from your network on port {port}, as plain HTTP" + ("; password required" if access.password else "")
              + ("; Home Assistant ingress accepted" if access.ingress else ""), flush=True)
    if args.open:
        import webbrowser

        webbrowser.open(url)
    try:
        await asyncio.Event().wait()
    finally:
        for task in tasks:
            task.cancel()
        if hub.source:
            hub.source.stop()
        await runner.cleanup()
