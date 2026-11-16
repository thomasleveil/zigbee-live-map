"""A small fake Hue bridge: HTTPS with a self-signed certificate, the link-button pairing and the CLIP v2 reads.

Used by tests/test_hue.py, and runnable on its own so the pages can be tried in a browser without a real bridge:

    python tests/fake_hue_bridge.py --port 8795 --demo

With --demo the devices are the ones of the simulated network (`zigbee-live-map --demo`), in a few rooms,
with two that are in trouble and one the simulated network does not contain. Nothing here is a real
identifier: every id, name and key is invented, and the key is drawn again at each start.

It answers like the real thing for what the tool uses and nothing more:
    GET  /api/0/config                  unauthenticated, the bridge id and name
    POST /api                           {"devicetype": ...} -> error 101 until the link button is "pressed"
    GET  /clip/v2/resource/<type>       needs the hue-application-key header
"""

from __future__ import annotations

import argparse
import asyncio
import copy
import datetime
import json
import ssl
import secrets
import tempfile
import time
import uuid
from pathlib import Path

from aiohttp import web
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

FIXTURE = Path(__file__).parent / "fixtures" / "hue_bridge.json"
DEFAULT_ID = "001788FFFE0A0B0C"
RESOURCES = ("device", "zigbee_connectivity", "room", "device_power")


def load_fixture() -> dict:
    data = json.loads(FIXTURE.read_text(encoding="utf-8"))
    return {name: data[name] for name in RESOURCES}


def _uid(label: str) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"fake-hue/{label}"))


def demo_resources() -> dict:
    """The simulated network seen from a bridge: same IEEE addresses, other names, a few rooms."""
    from zigbee_live_map import demo

    channel = 20    # the bridge's network; the simulated sniffer is on none, so no mismatch shows in demo mode

    # address: (bridge-side name, room, product, model, archetype)
    table = {
        demo.COORDINATOR: ("Hue Bridge", None, "Example bridge", "BR-1", "bridge_v2"),
        "0x2b01": ("Kitchen socket", "Kitchen", "Example smart plug", "SP-100", "plug"),
        "0x2b02": ("Lounge socket", "Living room", "Example smart plug", "SP-100", "plug"),
        "0x2b03": ("Garage socket", "Garage", "Example smart plug", "SP-100", "plug"),
        "0x2b04": ("Mains meter", "Hallway", "Example meter reader", "MR-200", "plug"),
        "0x7c01": ("Bedroom valve", "Bedroom", "Example radiator valve", "TRV-300", "unknown_archetype"),
        "0x7c02": ("Office valve", "Office", "Example radiator valve", "TRV-300", "unknown_archetype"),
        "0x7c03": ("Hall motion sensor", "Hallway", "Example motion sensor", "PIR-400", "unknown_archetype"),
        "0x7c04": ("Garage door sensor", "Garage", "Example contact sensor", "CNT-500", "unknown_archetype"),
        "0x7c05": ("Garden thermometer", "Garden", "Example weather sensor", "WX-600", "unknown_archetype"),
        "0x7c06": ("Bathroom hygrometer", "Bathroom", "Example weather sensor", "WX-600", "unknown_archetype"),
        "0x7c07": ("Entrance contact", "Hallway", "Example contact sensor", "CNT-500", "unknown_archetype"),
    }
    # In trouble: one with connection problems, one that is gone. The extra device is on no radio the sniffer hears.
    status = {"0x7c05": "connectivity_issue", "0x7c04": "disconnected", "extra": "unidirectional_incoming"}
    rows = [(addr, demo.ieee_of(addr), *spec) for addr, spec in table.items()]
    rows.append(("extra", "02:00:00:ff:fe:00:7c:99", "Porch light", "Garden", "Example light", "LT-700", "sultan_bulb"))
    devices, connectivity, power, rooms = [], [], [], {}
    for addr, ieee, name, room, product, model, archetype in rows:
        did, zid = _uid(f"device/{addr}"), _uid(f"zc/{addr}")
        devices.append({"id": did, "product_data": {"model_id": model, "manufacturer_name": "Example Devices Ltd", "product_name": product,
                                                    "product_archetype": archetype, "certified": True, "software_version": "1.0.0"},
                        "metadata": {"name": name, "archetype": archetype},
                        "services": [{"rid": zid, "rtype": "zigbee_connectivity"}], "type": "device"})
        connectivity.append({"id": zid, "owner": {"rid": did, "rtype": "device"}, "status": status.get(addr, "connected"),
                             "mac_address": ieee, "type": "zigbee_connectivity",
                             **({"channel": {"status": "set", "value": f"channel_{channel}"}} if addr == demo.COORDINATOR else {})})
        if addr in demo.BATTERY:
            level = demo.BATTERY[addr]
            power.append({"id": _uid(f"power/{addr}"), "owner": {"rid": did, "rtype": "device"}, "type": "device_power",
                          "power_state": {"battery_state": "low" if level <= 15 else "normal", "battery_level": level}})
        if room:
            rooms.setdefault(room, []).append({"rid": did, "rtype": "device"})
    room_rows = [{"id": _uid(f"room/{name}"), "children": kids, "services": [], "metadata": {"name": name, "archetype": "other"}, "type": "room"}
                 for name, kids in rooms.items()]
    return {name: {"errors": [], "data": data} for name, data in
            (("device", devices), ("zigbee_connectivity", connectivity), ("room", room_rows), ("device_power", power))}


def make_certificate(common_name: str) -> tuple[bytes, bytes]:
    """A self-signed certificate (PEM) whose common name is `common_name`, like the bridges that sign themselves."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=3650)).sign(key, hashes.SHA256()))
    return (cert.public_bytes(serialization.Encoding.PEM),
            key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))


class FakeBridge:
    """`bridge_id` is what the bridge announces; `cn` (default: the same) is what its certificate says."""

    def __init__(self, resources: dict | None = None, *, bridge_id: str = DEFAULT_ID, cn: str | None = None, name: str = "Hue Bridge",
                 app_key: str | None = None, press_after: float = 0.0) -> None:
        self.resources = copy.deepcopy(resources if resources is not None else load_fixture())
        self.bridge_id, self.cn, self.name = bridge_id, cn if cn is not None else bridge_id, name
        self.app_key = app_key or secrets.token_urlsafe(30)
        self.press_after = press_after          # seconds after the first pairing attempt until the button counts as pressed
        self.requests: list[tuple[str, str]] = []
        self.pair_attempts = 0
        self.port = 0
        self._first_attempt: float | None = None
        self._runner: web.AppRunner | None = None
        self._tmp = tempfile.TemporaryDirectory(prefix="fake-hue-")

    # ---- what a test can change
    def set_status(self, ieee: str, status: str) -> None:
        for row in self.resources["zigbee_connectivity"]["data"]:
            if row["mac_address"] == ieee:
                row["status"] = status

    # ---- the server
    def _ssl(self) -> ssl.SSLContext:
        pem, key = make_certificate(self.cn)
        folder = Path(self._tmp.name)
        (folder / "cert.pem").write_bytes(pem)
        (folder / "key.pem").write_bytes(key)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(folder / "cert.pem", folder / "key.pem")
        return context

    async def start(self, port: int = 0, host: str = "127.0.0.1") -> int:
        app = web.Application()
        app.add_routes([web.get("/api/0/config", self._config), web.get("/api/config", self._config), web.post("/api", self._pair),
                        web.get("/clip/v2/resource/{rtype}", self._resource)])
        self._runner = web.AppRunner(app, access_log=None)
        await self._runner.setup()
        site = web.TCPSite(self._runner, host, port, ssl_context=self._ssl())
        await site.start()
        self.port = self._runner.addresses[0][1]
        return self.port

    async def stop(self) -> None:
        if self._runner:
            await self._runner.cleanup()
            self._runner = None

    async def restart(self, *, cn: str | None = None) -> None:
        """Same address, a new certificate (every start makes one): a replaced or reset bridge, or someone in the middle."""
        await self.stop()
        if cn is not None:
            self.cn = cn
        await self.start(self.port)

    def close(self) -> None:
        self._tmp.cleanup()

    # ---- the handlers
    def _log(self, request: web.Request) -> None:
        self.requests.append((request.method, request.path))

    async def _config(self, request: web.Request) -> web.Response:
        self._log(request)
        return web.json_response({"name": self.name, "bridgeid": self.bridge_id, "modelid": "BSB002", "apiversion": "1.65.0", "swversion": "1976154040"})

    def _pressed(self) -> bool:
        return self._first_attempt is not None and time.monotonic() - self._first_attempt >= self.press_after

    async def _pair(self, request: web.Request) -> web.Response:
        self._log(request)
        self.pair_attempts += 1
        if self._first_attempt is None:
            self._first_attempt = time.monotonic()
        try:
            body = await request.json()
        except ValueError:
            body = None
        if not isinstance(body, dict) or not body.get("devicetype"):
            return web.json_response([{"error": {"type": 2, "address": "/", "description": "body contains invalid json"}}])
        if not self._pressed():
            return web.json_response([{"error": {"type": 101, "address": "", "description": "link button not pressed"}}])
        return web.json_response([{"success": {"username": self.app_key}}])

    async def _resource(self, request: web.Request) -> web.Response:
        self._log(request)
        if request.headers.get("hue-application-key") != self.app_key:
            return web.json_response([{"error": {"type": 1, "address": request.path, "description": "unauthorized user"}}], status=403)
        data = self.resources.get(request.match_info["rtype"])
        if data is None:
            return web.json_response({"errors": [{"description": "Not Found"}], "data": []}, status=404)
        # A real bridge sends a resource list in many pieces: a client that reads only the first one gets half a document.
        body = json.dumps(data).encode()
        response = web.StreamResponse(headers={"Content-Type": "application/json"})
        await response.prepare(request)
        for start in range(0, len(body), 256):
            await response.write(body[start:start + 256])
            await asyncio.sleep(0.001)
        await response.write_eof()
        return response


async def _serve(args: argparse.Namespace) -> None:
    bridge = FakeBridge(demo_resources() if args.demo else None, bridge_id=args.bridge_id, press_after=args.press_after)
    port = await bridge.start(args.port, args.host)
    print(f"Fake Hue bridge on https://{args.host}:{port}  (bridge id {bridge.bridge_id}, self-signed certificate)", flush=True)
    print(f"Application key: {bridge.app_key}", flush=True)
    print(f'Pairing: the link button counts as pressed {args.press_after:g} s after the first attempt. Ctrl-C to stop.', flush=True)
    try:
        await asyncio.Event().wait()
    finally:
        await bridge.stop()
        bridge.close()


def main() -> None:
    ap = argparse.ArgumentParser(description="A fake Hue bridge for trying zigbee-live-map without one.")
    ap.add_argument("--port", type=int, default=8795)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--demo", action="store_true", help="serve the devices of the simulated network (zigbee-live-map --demo)")
    ap.add_argument("--press-after", type=float, default=4.0, metavar="SECONDS", help="link button pressed this long after the first pairing attempt (default 4)")
    ap.add_argument("--bridge-id", default=DEFAULT_ID)
    try:
        asyncio.run(_serve(ap.parse_args()))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
