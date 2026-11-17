"""Home Assistant device names: the names the user already gave their Zigbee devices, matched by IEEE address.

When the tool runs as a Home Assistant app, Home Assistant already knows a friendly name for every Zigbee device
the user set up (through ZHA, Zigbee2MQTT or another integration). A passive sniffer cannot read those names off
the air, but Home Assistant's own device registry keeps them next to each device's IEEE address. This reads that
registry and offers (IEEE -> name) as a fallback the user's own lists still override, through the same seam as the
Hue path (`fallback_names`), so the precedence is the one the user already knows: their lists and imports win.

Inert unless Home Assistant started the tool. The Supervisor sets SUPERVISOR_TOKEN in every app container, and that
token is both the signal that we are an app and the credential for the call; with no token nothing here reaches the
network and nothing is contacted. With a token but without the `homeassistant_api` manifest key, Home Assistant
refuses the call, which degrades to no names, quietly.

The IEEE<->name mapping lives in the device registry, which the REST `/api/states` endpoint does not carry (it has
the friendly name but not the IEEE), so this uses Home Assistant's WebSocket API at http://supervisor/core/websocket.
The exchange is the documented one (developers.home-assistant.io/docs/api/websocket): the server asks to authenticate,
the token is sent, and on `auth_ok` the device registry is requested. This WebSocket path — that the Supervisor proxy
accepts the Supervisor token in a plain `auth` frame, and the exact JSON of a device-registry entry — is the DOCUMENTED
shape, from Home Assistant's own docs and source (helpers/device_registry.py `CONNECTION_ZIGBEE = "zigbee"`); it is not
something this repository verifies against a live instance. What was proven on the bench is the REST reachability only
(`homeassistant_api: true` -> 200). For ZHA each device carries a `("zigbee", <ieee>)` connection; it is matched
case-insensitively on the tag and the IEEE is normalised the same way as the rest of the tool. Other integrations
(Zigbee2MQTT, the Hue integration) shape the registry differently: any ("zigbee", <hex>) connection that normalises is
still used, and everything else is skipped without error. A device already on the Hue bridge is simply named by the Hue
path as before; naming it again here changes nothing.

The token is a secret: it is sent only in the auth frame, never logged, never placed in an error text, never in a URL.
"""

from __future__ import annotations

import asyncio
import time
from typing import Awaitable, Callable

import aiohttp

from .devices import DeviceError, normalise_ieee

CORE_WS_URL = "http://supervisor/core/websocket"   # the Supervisor proxies this to Home Assistant Core
REFRESH_SECONDS = 300.0        # device names change rarely; a slow periodic read keeps the map current without noise
EXCHANGE_TIMEOUT = 20.0        # the whole connect-authenticate-read exchange; nothing here may wait unbounded
MAX_MSG_SIZE = 8 * 1024 * 1024  # a large home's registry still fits; a bigger message is refused, not read
MAX_MESSAGES = 64              # messages read while waiting for our result, so a chatty connection cannot hold us open
MAX_NAME = 60                  # the same length a user's own device entry is trimmed to (devices.MAX_TEXT)
ZIGBEE = "zigbee"              # the connection type ZHA records for a Zigbee device: ("zigbee", <ieee>)
REGISTRY_COMMAND = "config/device_registry/list"

Notify = Callable[[], Awaitable[None]]


class HaError(DeviceError):
    """Always a plain sentence: never the token, never the registry, never raw exception text."""


def device_names(result: object) -> dict[str, str]:
    """(IEEE -> friendly name) from a `config/device_registry/list` result.

    The friendly name is the user's override (`name_by_user`) when set, else the integration's `name`. A device is
    matched on its first ("zigbee", <ieee>) connection whose value normalises the way the rest of the tool normalises
    an IEEE. A device with no such connection, or no name, is skipped. Nothing here raises on an unexpected shape.
    """
    names: dict[str, str] = {}
    for device in result if isinstance(result, list) else ():
        if not isinstance(device, dict):
            continue
        label = device.get("name_by_user") or device.get("name")
        if not isinstance(label, str):
            continue
        label = " ".join(label.split())[:MAX_NAME]
        if not label:
            continue
        for connection in device.get("connections") or ():
            if not (isinstance(connection, (list, tuple)) and len(connection) == 2):
                continue
            tag, value = connection
            # The tag is "zigbee" in Home Assistant's source (helpers/device_registry.py CONNECTION_ZIGBEE); match it
            # case-insensitively so a casing difference in the JSON does not silently drop a device. The IEEE is then
            # normalised the one way the rest of the tool normalises one, so casing or a 0x prefix there do not matter.
            if isinstance(tag, str) and tag.lower() == ZIGBEE and isinstance(value, str):
                ieee = normalise_ieee(value)
                if ieee:
                    names.setdefault(ieee, label)
                    break
    return names


async def fetch_device_names(session: aiohttp.ClientSession, url: str, token: str) -> dict[str, str]:
    """Open the WebSocket, authenticate with the Supervisor token, ask for the device registry, parse the names.

    The documented Home Assistant handshake: the server sends `auth_required`, the token is sent in an `auth` frame,
    the server answers `auth_ok` (or `auth_invalid`), then a command is sent and its `result` returned. Any events or
    unrelated results that arrive first are skipped, up to a bound.
    """
    async with session.ws_connect(url, max_msg_size=MAX_MSG_SIZE, heartbeat=None) as ws:
        hello = await ws.receive_json()
        if not (isinstance(hello, dict) and hello.get("type") == "auth_required"):
            raise HaError("Home Assistant did not begin the expected authentication.")
        await ws.send_json({"type": "auth", "access_token": token})
        ack = await ws.receive_json()
        if not (isinstance(ack, dict) and ack.get("type") == "auth_ok"):
            raise HaError("Home Assistant did not accept the Supervisor token for its API.")
        await ws.send_json({"id": 1, "type": REGISTRY_COMMAND})
        for _ in range(MAX_MESSAGES):
            message = await ws.receive_json()
            if isinstance(message, dict) and message.get("type") == "result" and message.get("id") == 1:
                if not message.get("success"):
                    raise HaError("Home Assistant refused the device registry request.")
                return device_names(message.get("result"))
        raise HaError("Home Assistant did not return the device registry.")


def _plain(exc: BaseException) -> str:
    """Every failure becomes a fixed sentence: a raw exception could carry the URL or a reply."""
    if isinstance(exc, HaError):
        return str(exc)
    if isinstance(exc, (asyncio.TimeoutError, TimeoutError)):
        return "Home Assistant did not answer in time."
    if isinstance(exc, (aiohttp.ClientError, OSError)):
        return "Could not reach Home Assistant's API."
    return "Something unexpected went wrong reading Home Assistant's device names."


class HaNames:
    """Home Assistant's device names, read on a slow loop while the Supervisor is the one who started the tool.

    A token of None (or empty) keeps it inert: `active` is false, `fallback_names` is empty, `refresh` contacts
    nothing and `start` creates no task. This is the state outside Home Assistant, and the state the tests rely on.
    """

    def __init__(self, token: str | None, *, url: str = CORE_WS_URL, on_change: Notify | None = None,
                 interval: float = REFRESH_SECONDS) -> None:
        self._token = token.strip() if isinstance(token, str) and token.strip() else None
        self._url = url
        self.on_change = on_change
        self._interval = interval
        self.names: dict[str, str] = {}
        self.last_read: float | None = None
        self.error: str | None = None
        self._logged: str | None = None   # the last state written to the log, so each change is logged at most once
        self._task: asyncio.Task | None = None

    @property
    def active(self) -> bool:
        """Whether a Supervisor token was given: the one gate on contacting Home Assistant at all."""
        return self._token is not None

    def fallback_names(self) -> dict[str, dict]:
        """The names, in the shape the naming seam consumes. The caller lets the user's lists win; nothing is written."""
        return {ieee: {"name": name} for ieee, name in self.names.items()}

    async def refresh(self) -> None:
        """Read the device registry once. Inert without a token. A failure keeps the last good names and is logged once."""
        if self._token is None:
            return
        before = self.names
        try:
            timeout = aiohttp.ClientTimeout(total=EXCHANGE_TIMEOUT)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                names = await asyncio.wait_for(fetch_device_names(session, self._url, self._token), EXCHANGE_TIMEOUT)
            self.names, self.last_read = names, time.time()
            self._note(None)
        except asyncio.CancelledError:
            raise
        except Exception as exc:   # whatever it is, the loop keeps running and the token never reaches the log
            self._note(_plain(exc))
        if self.names != before:
            await self._changed()

    def start(self, read_now: bool = True) -> None:
        """Begin the periodic read, only when a token was given. Does nothing, and starts nothing, otherwise."""
        if self._token is not None and (self._task is None or self._task.done()):
            self._task = asyncio.create_task(self._loop(read_now))

    async def _loop(self, read_now: bool) -> None:
        if not read_now:
            await asyncio.sleep(self._interval)
        while True:
            await self.refresh()
            await asyncio.sleep(self._interval)

    async def stop(self) -> None:
        if self._task is not None and not self._task.done():
            self._task.cancel()
            await asyncio.gather(self._task, return_exceptions=True)

    def _note(self, error: str | None) -> None:
        """Hold the current error and write one log line per change of state: into a fault, and back out of it."""
        self.error = error
        if error == self._logged:
            return
        self._logged = error
        if error is not None:
            print(f"home assistant: {error}", flush=True)
        elif self.last_read is not None:
            print("home assistant: device names are being read again.", flush=True)

    async def _changed(self) -> None:
        if self.on_change:
            await self.on_change()
