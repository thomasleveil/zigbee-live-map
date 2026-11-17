"""Home Assistant device names: parsing, the precedence seam, the inert state, and the live WebSocket read.

No test here touches a real Home Assistant, a real dongle or a real IEEE: the device-registry payloads and the
addresses are synthetic, and the one live read runs against an in-process WebSocket server that plays Home Assistant.
Select with -k "ha and parse", "ha and inert", "ha and precedence", "ha and match" or "ha and websocket".
"""
from __future__ import annotations

import asyncio

import pytest
from aiohttp import web
from aiohttp.test_utils import TestServer

from zigbee_live_map import decode, ha
from zigbee_live_map.access import SUPERVISOR_ENV
from zigbee_live_map.devices import DeviceStore
from zigbee_live_map.ha import HaNames, device_names
from zigbee_live_map.server import Hub
from zigbee_live_map.vendors import Registry

INFO = {"channel": None, "mode": "replay", "focus": None, "can_tune": False}
NET = bytes.fromhex("0f1e2d3c4b5a69788796a5b4c3d2e1f0")
DEV64 = 0x00158D00_01A2B3C4
DEV_IEEE = "00:15:8d:00:01:a2:b3:c4"   # how DEV64 reads as an IEEE: the form the sniffer and the lists use


def zha_device(name, ieee, *, name_by_user=None, extra_connections=()):
    """A device-registry entry shaped the way ZHA records one: a ("zigbee", <ieee>) connection."""
    return {"id": "dev-" + ieee.replace(":", ""), "name": name, "name_by_user": name_by_user,
            "connections": [*extra_connections, ["zigbee", ieee]], "identifiers": [["zha", ieee]]}


def hub_with(ha_names, tmp_path, store=None):
    hub = Hub(store if store is not None else DeviceStore(None), Registry(tmp_path), dict(INFO), 100, ha=ha_names)
    return hub


# --------------------------------------------------------------------------- parsing

def test_ha_parse_reads_ieee_and_friendly_name_from_a_zha_registry():
    result = [zha_device("Kitchen motion", "00:12:4B:00:11:22:33:44")]
    assert device_names(result) == {"00:12:4b:00:11:22:33:44": "Kitchen motion"}


def test_ha_parse_prefers_the_users_own_override_name():
    result = [zha_device("lumi.sensor_motion", "00:12:4b:00:11:22:33:44", name_by_user="Hallway sensor")]
    assert device_names(result) == {"00:12:4b:00:11:22:33:44": "Hallway sensor"}


def test_ha_parse_normalises_the_address_the_same_way_as_the_rest_of_the_tool():
    # Upper case, 0x prefix and no separators all collapse to the one canonical form the sniffer emits.
    for written in ("00:15:8D:00:01:A2:B3:C4", "0x00158d0001a2b3c4", "00158D0001A2B3C4"):
        assert device_names([zha_device("Lamp", written)]) == {DEV_IEEE: "Lamp"}


@pytest.mark.parametrize("result", [
    [{"name": "No zigbee", "connections": [["mac", "aa:bb"]]}],        # a device, but not a Zigbee one
    [{"name": "No connections at all"}],                               # no connections key
    [{"name": "Broken conns", "connections": "not-a-list"}],          # connections is not a list
    [{"name": "Short conn", "connections": [["zigbee"]]}],            # a one-element connection
    [{"connections": [["zigbee", "00:12:4b:00:11:22:33:44"]]}],       # a Zigbee device with no name
    [{"name": "Bad ieee", "connections": [["zigbee", "not-an-ieee"]]}],  # a Zigbee connection that does not normalise
    ["not-a-dict", 42, None],                                          # entries that are not devices
    {"result": "not a list"},                                         # the whole thing is not a list
    [],
])
def test_ha_parse_skips_unknown_shapes_without_error(result):
    assert device_names(result) == {}


def test_ha_parse_matches_the_zigbee_tag_case_insensitively():
    # Home Assistant's source constant is the lowercase "zigbee" (CONNECTION_ZIGBEE) — the DOCUMENTED shape, not one
    # verified here against a live instance. The parser lower-cases the tag so a casing difference cannot drop a device.
    for tag in ("zigbee", "Zigbee", "ZIGBEE"):
        assert device_names([{"name": "Porch", "connections": [[tag, "00:12:4b:00:aa:bb:cc:dd"]]}]) == {
            "00:12:4b:00:aa:bb:cc:dd": "Porch"}


def test_ha_parse_tolerates_a_non_zha_shape_but_uses_any_zigbee_connection_it_can_match():
    # A Zigbee2MQTT / Hue-integration entry is UNVERIFIED in shape; where it still carries ("zigbee", <hex>) it is used.
    hue_like = {"name": "Living room bulb", "name_by_user": None,
                "connections": [["mac", "00:11:22:33"], ["zigbee", "00:17:88:01:0a:0b:0c:0d"]]}
    assert device_names([hue_like]) == {"00:17:88:01:0a:0b:0c:0d": "Living room bulb"}


# --------------------------------------------------------------------------- inert outside Home Assistant

def test_ha_inert_without_a_token_contacts_nothing(monkeypatch):
    def fail(*_a, **_k):
        raise AssertionError("no network call may be made without a Supervisor token")

    monkeypatch.setattr(ha, "fetch_device_names", fail)

    async def main():
        service = HaNames(None)
        assert service.active is False
        assert service.fallback_names() == {}
        service.start()                 # creates no task
        assert service._task is None
        await service.refresh()         # makes no call, raises nothing
        assert service.fallback_names() == {} and service.error is None

    asyncio.run(main())


def test_ha_inert_gate_is_the_supervisor_token_read_in_serve(monkeypatch):
    # The exact expression serve() uses to decide whether the feature is live.
    monkeypatch.delenv(SUPERVISOR_ENV, raising=False)
    import os

    assert HaNames(os.environ.get(SUPERVISOR_ENV)).active is False
    assert HaNames("").active is False and HaNames("   ").active is False
    monkeypatch.setenv(SUPERVISOR_ENV, "a-supervisor-token")
    assert HaNames(os.environ.get(SUPERVISOR_ENV)).active is True


def test_ha_serve_in_demo_mode_never_reads_home_assistant(tmp_path, monkeypatch):
    """Even with a Supervisor token in the environment, the demo contacts nothing: the token is not even read."""
    import types

    from zigbee_live_map import server

    monkeypatch.setenv(SUPERVISOR_ENV, "a-supervisor-token")
    monkeypatch.setattr(ha, "fetch_device_names", lambda *a, **k: (_ for _ in ()).throw(AssertionError("demo must not call HA")))
    seen = []

    class Stop(Exception):
        pass

    def stop(hub, *_a, **_k):
        seen.append(hub)
        raise Stop

    monkeypatch.setattr(server, "build_app", stop)
    args = types.SimpleNamespace(demo=True, replay=None, data_dir=str(tmp_path), channel=11, focus=None,
                                 backlog=100, speed=1.0, pcap=None, port=0, open=False)
    with pytest.raises(Stop):
        asyncio.run(server.serve(args, None))
    assert seen[0].ha.active is False


# --------------------------------------------------------------------------- precedence through the naming seam

def test_ha_precedence_a_users_own_name_wins_over_home_assistant(tmp_path):
    store = DeviceStore(None)
    list_id = store.create("Home")
    store.set_device(list_id, DEV_IEEE, {"name": "My doorbell"})
    service = HaNames(None)
    service.names = {DEV_IEEE: "Front door (HA)"}
    names = hub_with(service, tmp_path, store).names()
    assert names[DEV_IEEE]["name"] == "My doorbell"   # the user's list wins, HA does not override it


def test_ha_precedence_fills_a_nameless_entry_and_keeps_its_other_fields(tmp_path):
    # A list entry with only a model (which import allows) borrows the HA name but stays the user's entry.
    store = DeviceStore(None)
    _name, devices = __import__("zigbee_live_map.devices", fromlist=["parse_import"]).parse_import(
        '{"name": "Imported", "devices": {"' + DEV_IEEE + '": {"model": "lumi.weather"}}}')
    store.lists["imported"] = {"name": "Imported", "enabled": True, "devices": devices}
    service = HaNames(None)
    service.names = {DEV_IEEE: "Study climate"}
    entry = hub_with(service, tmp_path, store).names()[DEV_IEEE]
    assert entry["name"] == "Study climate" and entry["model"] == "lumi.weather"


def test_ha_precedence_an_imported_named_device_still_wins(tmp_path):
    store = DeviceStore(None)
    list_id = store.create("Home")
    store.import_text(list_id, "name,ieee\nGarage plug," + DEV_IEEE + "\n")
    service = HaNames(None)
    service.names = {DEV_IEEE: "Garage (HA)"}
    assert hub_with(service, tmp_path, store).names()[DEV_IEEE]["name"] == "Garage plug"


def test_ha_name_shows_for_a_device_no_list_names(tmp_path):
    service = HaNames(None)
    service.names = {DEV_IEEE: "Bedroom sensor"}
    assert hub_with(service, tmp_path).names()[DEV_IEEE] == {"name": "Bedroom sensor"}


# --------------------------------------------------------------------------- matching the device the sniffer heard

def test_ha_match_a_sniffed_device_shows_its_home_assistant_name(tmp_path):
    """End to end: the IEEE the Classifier emits for a real frame is the key an HA registry entry resolves to."""
    async def main():
        service = HaNames(None)
        hub = hub_with(service, tmp_path)
        frame = decode.build_secured_nwk(NET, seq=5, pan=0x1A62, mac_dst=0x0000, mac_src=0x72F6,
                                         nwk_dst=0x0000, nwk_src=0x72F6, radius=30, nwk_seq=5,
                                         src64=DEV64, counter=42, payload=decode.zcl_basic_response("LUMI", "lumi.weather", power=3))
        await hub.publish(frame, 1.0, None)
        heard_ieee = hub.events[-1]["ieee"]              # the exact string the Classifier produced from the air
        # The HA registry carries the same address, written in Home Assistant's own casing.
        service.names = device_names([zha_device("Weather sensor", heard_ieee.upper())])
        assert heard_ieee == DEV_IEEE                    # and it is the canonical form the rest of the tool uses
        assert hub.names()[heard_ieee]["name"] == "Weather sensor"

    asyncio.run(main())


# --------------------------------------------------------------------------- the live WebSocket read

def fake_core(result, *, accept=True, seen=None):
    """An in-process server that plays Home Assistant Core's WebSocket API for one exchange."""
    async def handler(request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        await ws.send_json({"type": "auth_required", "ha_version": "2026.11.0"})
        auth = await ws.receive_json()
        if seen is not None:
            seen.append(auth)
        if auth.get("type") != "auth" or not auth.get("access_token"):
            await ws.send_json({"type": "auth_invalid", "message": "need a token"})
            await ws.close()
            return ws
        if not accept:
            await ws.send_json({"type": "auth_invalid", "message": "bad token"})
            await ws.close()
            return ws
        await ws.send_json({"type": "auth_ok", "ha_version": "2026.11.0"})
        command = await ws.receive_json()
        assert command.get("type") == ha.REGISTRY_COMMAND
        await ws.send_json({"id": command["id"], "type": "result", "success": True, "result": result})
        await ws.close()
        return ws

    app = web.Application()
    app.add_routes([web.get("/core/websocket", handler)])
    return app


def ws_url(server: TestServer) -> str:
    return f"http://127.0.0.1:{server.port}/core/websocket"


def test_ha_websocket_reads_the_registry_through_the_documented_handshake(tmp_path):
    result = [zha_device("Kitchen motion", "00:12:4b:00:11:22:33:44"),
              zha_device("lumi.plug", "00:15:8d:00:01:a2:b3:c4", name_by_user="Desk lamp")]
    seen_auth: list = []

    async def main():
        server = TestServer(fake_core(result, seen=seen_auth))
        await server.start_server()
        try:
            service = HaNames("the-supervisor-token", url=ws_url(server))
            await service.refresh()
        finally:
            await server.close()
        assert service.active is True and service.error is None and service.last_read is not None
        assert service.names == {"00:12:4b:00:11:22:33:44": "Kitchen motion", "00:15:8d:00:01:a2:b3:c4": "Desk lamp"}
        assert service.fallback_names()["00:15:8d:00:01:a2:b3:c4"] == {"name": "Desk lamp"}
        # the token travelled only in the auth frame, in the documented field
        assert seen_auth and seen_auth[0]["access_token"] == "the-supervisor-token"

    asyncio.run(main())


def test_ha_websocket_rejected_token_is_quiet_and_names_stay_empty(tmp_path, capsys):
    async def main():
        server = TestServer(fake_core([], accept=False))
        await server.start_server()
        try:
            service = HaNames("the-supervisor-token", url=ws_url(server))
            await service.refresh()
        finally:
            await server.close()
        assert service.names == {} and service.error is not None   # a failure, reported, not raised
        return service.error

    error = asyncio.run(main())
    out = capsys.readouterr().out
    assert "the-supervisor-token" not in out and "the-supervisor-token" not in error   # the token never leaks


def test_ha_refresh_keeps_the_last_good_names_when_a_later_read_fails(tmp_path, capsys):
    good = [zha_device("Porch light", "00:12:4b:00:aa:bb:cc:dd")]

    async def main():
        ok = TestServer(fake_core(good))
        await ok.start_server()
        service = HaNames("tok", url=ws_url(ok))
        await service.refresh()
        await ok.close()
        assert service.names == {"00:12:4b:00:aa:bb:cc:dd": "Porch light"}
        # Point at a dead address: the read fails, the last good names survive, one error line is logged.
        service._url = "http://127.0.0.1:0/core/websocket"
        await service.refresh()
        assert service.names == {"00:12:4b:00:aa:bb:cc:dd": "Porch light"} and service.error is not None

    asyncio.run(main())
    assert capsys.readouterr().out.count("home assistant:") == 1   # one line for the fault, the good read was silent
