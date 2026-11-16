"""Hue Bridge integration, against tests/fake_hue_bridge.py (HTTPS, self-signed) and with the network discovery faked.

No test here touches a real bridge or the real network: discovery is replaced, and the only bridge is the fake one on loopback.
Select a group with -k "hue and discover", "hue and pair", "hue and tls", "hue and enrich" or "hue and idle".
"""
import asyncio
import json
import stat
import types

import pytest
from aiohttp.test_utils import TestClient, TestServer
from fake_hue_bridge import FakeBridge

from zigbee_live_map import hue
from zigbee_live_map.devices import DeviceStore
from zigbee_live_map.hue import HueService
from zigbee_live_map.server import Hub, build_app
from zigbee_live_map.vendors import Registry

BRIDGE_ID = "001788FFFE0A0B0C"
LAMP, STRIP, BEDROOM_LAMP, DIMMER, BRIDGE = (f"00:17:88:01:0a:0b:0c:{n}" for n in ("0d", "0e", "0f", "10", "01"))
INFO = {"channel": None, "mode": "replay", "focus": None, "can_tune": False}


class Api:
    """Calls the tool's own API as its page does, and keeps every byte it answered, to look for secrets in."""

    def __init__(self, client, origin):
        self.client, self.origin, self.seen = client, origin, []

    async def __call__(self, method, path, body=None):
        response = await self.client.request(method, path, json=body, headers=self.origin)
        text = await response.text()
        self.seen.append(text)
        try:
            return response.status, json.loads(text)
        except ValueError:
            return response.status, text


def run(scenario, tmp_path, monkeypatch, **bridge):
    """Start the fake bridge and the tool in one loop; pairing retries fast so a test does not wait 30 s."""
    monkeypatch.setattr(hue, "PAIR_INTERVAL", 0.03)
    monkeypatch.setattr(hue, "PAIR_TIMEOUT", 5.0)

    async def main():
        fake = FakeBridge(**bridge)
        await fake.start()
        hub = Hub(DeviceStore(tmp_path), Registry(tmp_path), dict(INFO), 100, hue=HueService(tmp_path))
        try:
            async with TestClient(TestServer(build_app(hub), host="127.0.0.1")) as client:
                token = (await (await client.get("/api/session")).json())["token"]
                origin = {"Origin": f"http://127.0.0.1:{client.server.port}", "X-ZLM-Token": token}
                await scenario(client, hub, origin, fake)
        finally:
            await fake.stop()
            fake.close()

    asyncio.run(main())


async def until(check, seconds=5.0):
    for _ in range(int(seconds / 0.02)):
        if check():
            return
        await asyncio.sleep(0.02)
    raise AssertionError("timed out waiting")


async def drain(ws, seconds=0.4):
    texts = []
    while True:
        try:
            texts.append(await asyncio.wait_for(ws.receive_str(), seconds))
        except asyncio.TimeoutError:
            return texts


async def set_up(api, bridge):
    status, body = await api("POST", "/api/hue/key", {"host": f"127.0.0.1:{bridge.port}", "key": bridge.app_key})
    assert status == 200 and body["configured"] is True, body
    return body


DIALLED: list = []


@pytest.fixture(autouse=True)
def _nothing_dialled():
    DIALLED.clear()
    yield


def boom(*args, **_kwargs):
    """Stands in for every way out to the network. Recorded, because the tool turns an exception into a plain message."""
    DIALLED.append(args)
    raise AssertionError("the tool contacted a bridge, or looked for one, when it was not asked to")


# ------------------------------------------------------------------------------------------ discover

RECORDS = [
    {"name": "Hue Bridge - 0A0B0C._hue._tcp.local.", "addresses": ["fe80::1", "10.0.0.12"], "port": 443,
     "properties": {b"bridgeid": b"001788FFFE0A0B0C", b"modelid": b"BSB002"}},
    {"name": "Hue Bridge - 0A0B0D._hue._tcp.local.", "addresses": ["10.0.0.13"], "port": 8443, "properties": None},
    {"name": "Somebody else on the internet._hue._tcp.local.", "addresses": ["93.184.216.34"], "port": 443, "properties": {}},
]


def test_hue_discover_parses_what_the_network_announces():
    parsed = hue.parse_service(RECORDS[0])
    assert parsed == {"name": "Hue Bridge - 0A0B0C", "bridgeId": "001788FFFE0A0B0C", "host": "10.0.0.12"}   # IPv4 first, default port left out
    assert hue.parse_service(RECORDS[1]) == {"name": "Hue Bridge - 0A0B0D", "bridgeId": None, "host": "10.0.0.13:8443"}
    assert hue.parse_service(RECORDS[2]) is None   # an address outside the private ranges is never offered
    odd = {"name": "x._hue._tcp.local.", "addresses": ["10.0.0.14"], "port": 443, "properties": {"bridgeid": "zz", b"modelid": None}}
    assert hue.parse_service(odd)["bridgeId"] is None   # not a bridge id: ignored, not trusted


def test_hue_discover_lists_bridges_only_when_asked(tmp_path, monkeypatch):
    calls = []

    async def fake_browse(timeout):
        calls.append(timeout)
        return RECORDS

    monkeypatch.setattr(hue, "browse_mdns", fake_browse)

    async def scenario(client, hub, origin, bridge):
        api = Api(client, origin)
        assert (await client.get("/api/hue/discover")).status in (404, 405) and calls == []   # a plain read never searches the network
        assert (await client.post("/api/hue/discover")).status == 403 and calls == []          # not without this page's token
        status, body = await api("POST", "/api/hue/discover")
        assert status == 200 and len(calls) == 1
        assert body == {"bridges": [{"name": "Hue Bridge - 0A0B0C", "bridgeId": "001788FFFE0A0B0C", "host": "10.0.0.12"},
                                    {"name": "Hue Bridge - 0A0B0D", "bridgeId": None, "host": "10.0.0.13:8443"}]}

    run(scenario, tmp_path, monkeypatch)


# ------------------------------------------------------------------------------------------ pair

def test_hue_pair_waits_for_the_button_stores_the_key_and_never_shows_it(tmp_path, monkeypatch, capsys):
    async def scenario(client, hub, origin, bridge):
        api, host = Api(client, origin), f"127.0.0.1:{bridge.port}"
        ws = await client.ws_connect(f"/ws?token={origin['X-ZLM-Token']}", headers=origin)
        assert (await client.post("/api/hue/pair", json={"host": host})).status == 403   # no token: not this tool's page
        assert bridge.pair_attempts == 0
        status, body = await api("POST", "/api/hue/pair", {"host": host})
        assert status == 200 and body["pairing"] == "waiting" and body["configured"] is False   # "press the link button"
        state = {}

        async def done():
            state.update((await api("GET", "/api/hue"))[1])
            return state["pairing"] != "waiting"
        while not await done():
            await asyncio.sleep(0.03)
        assert state["configured"] is True and state["pairing"] is None and state["error"] is None
        assert state["name"] == "Hue Bridge" and state["bridgeId"] == BRIDGE_ID and state["lastRead"]
        assert bridge.pair_attempts >= 3                         # error 101 came back until the button was pressed
        path = tmp_path / "hue.json"
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        stored = json.loads(path.read_text())
        assert stored["key"] == bridge.app_key and len(stored["fingerprint"]) == 64
        assert hue.HueService(tmp_path).configured                # a later session finds it again
        texts = api.seen + await drain(ws) + [json.dumps(hub.hello()), json.dumps(hub.hue.status()), json.dumps(hub.hue.view())]
        out, err = capsys.readouterr()
        assert not [text for text in texts + [out, err] if bridge.app_key in text]   # nowhere: not in answers, pages, logs
        await ws.close()

    run(scenario, tmp_path, monkeypatch, press_after=0.2)


def test_hue_pair_gives_up_after_the_delay_with_nothing_stored(tmp_path, monkeypatch):
    async def scenario(client, hub, origin, bridge):
        api = Api(client, origin)
        monkeypatch.setattr(hue, "PAIR_TIMEOUT", 0.3)
        assert (await api("POST", "/api/hue/pair", {"host": f"127.0.0.1:{bridge.port}"}))[1]["pairing"] == "waiting"
        await until(lambda: hub.hue.pairing != "waiting")
        status, body = await api("GET", "/api/hue")
        assert body["pairing"] == "timeout" and body["configured"] is False
        assert bridge.pair_attempts >= 2 and not (tmp_path / "hue.json").exists()

    run(scenario, tmp_path, monkeypatch, press_after=3600)


def test_hue_pair_an_existing_key_is_checked_before_it_is_kept(tmp_path, monkeypatch):
    async def scenario(client, hub, origin, bridge):
        api, host = Api(client, origin), f"127.0.0.1:{bridge.port}"
        wrong = "x" * 40
        status, body = await api("POST", "/api/hue/key", {"host": host, "key": wrong})
        assert status == 400 and "key" in body["error"] and wrong not in json.dumps(body)
        assert not (tmp_path / "hue.json").exists()
        status, body = await api("POST", "/api/hue/key", {"host": host, "key": "bad key"})   # not even shaped like a key
        assert status == 400 and bridge.requests.count(("GET", "/clip/v2/resource/device")) == 1
        body = await set_up(api, bridge)
        assert body["name"] == "Hue Bridge" and "key" not in body and "fingerprint" not in body and "host" not in body
        assert stat.S_IMODE((tmp_path / "hue.json").stat().st_mode) == 0o600
        assert bridge.app_key not in "".join(api.seen)

    run(scenario, tmp_path, monkeypatch)


def test_hue_pair_forgetting_the_bridge_removes_the_key_and_what_came_from_it(tmp_path, monkeypatch):
    async def scenario(client, hub, origin, bridge):
        api = Api(client, origin)
        await set_up(api, bridge)
        assert hub.hue.view()["devices"]
        status, body = await api("DELETE", "/api/hue")
        assert status == 200 and body["configured"] is False
        assert not (tmp_path / "hue.json").exists() and hub.hue.view()["devices"] == {}
        before = len(bridge.requests)
        await api("POST", "/api/hue/refresh")
        assert len(bridge.requests) == before                       # nothing to refresh, nothing asked

    run(scenario, tmp_path, monkeypatch)


# ------------------------------------------------------------------------------------------ tls

def test_hue_tls_a_changed_certificate_is_refused_and_no_key_is_sent(tmp_path, monkeypatch):
    async def scenario(client, hub, origin, bridge):
        api = Api(client, origin)
        await set_up(api, bridge)
        known = dict(hub.hue.view()["devices"])
        await bridge.restart()                                     # same address and bridge id, another certificate
        bridge.requests.clear()
        status, body = await api("POST", "/api/hue/refresh")
        assert status == 200 and "certificate" in body["error"] and "forget" in body["error"].lower()
        assert bridge.requests == []                               # refused during the handshake: nothing, the key included, was sent
        assert hub.hue.view()["devices"] == known                  # what was known stays, marked by the error
        assert bridge.app_key not in "".join(api.seen)
        await api("DELETE", "/api/hue")                            # forget, set up again: the new certificate is pinned
        assert (await set_up(api, bridge))["error"] is None

    run(scenario, tmp_path, monkeypatch)


def test_hue_tls_a_certificate_for_another_bridge_is_refused_before_any_key_moves(tmp_path, monkeypatch):
    async def scenario(client, hub, origin, bridge):
        api, host = Api(client, origin), f"127.0.0.1:{bridge.port}"
        status, body = await api("POST", "/api/hue/pair", {"host": host})
        assert status == 400 and "common name" in body["error"]
        status, body = await api("POST", "/api/hue/key", {"host": host, "key": bridge.app_key})
        assert status == 400 and "common name" in body["error"] and bridge.app_key not in json.dumps(body)
        assert bridge.pair_attempts == 0                           # no pairing request, so no key was created
        assert not [path for _method, path in bridge.requests if path.startswith("/clip")]   # nor presented
        assert not (tmp_path / "hue.json").exists()

    run(scenario, tmp_path, monkeypatch, cn="FFFFFFFFFFFFFFFF")


def test_hue_tls_the_common_name_matches_whatever_the_letter_case(tmp_path, monkeypatch):
    async def scenario(client, hub, origin, bridge):
        await set_up(Api(client, origin), bridge)

    run(scenario, tmp_path, monkeypatch, bridge_id="001788FFFE0A0B0C", cn="001788fffe0a0b0c")


# ------------------------------------------------------------------------------------------ enrich

def test_hue_enrich_joins_each_device_to_the_map_on_its_ieee_address(tmp_path, monkeypatch):
    async def scenario(client, hub, origin, bridge):
        await set_up(Api(client, origin), bridge)
        devices = hub.hue.view()["devices"]
        assert devices[LAMP] == {"name": "Kitchen lamp", "product": "Hue color lamp", "model": "LCT015", "maker": "Signify Netherlands B.V.",
                                 "type": "sultan_bulb", "room": "Kitchen", "status": "connected", "battery": None}
        assert devices[DIMMER]["battery"] == {"level": 14, "state": "low"} and devices[DIMMER]["room"] == "Bedroom"
        assert devices[BRIDGE]["room"] is None and devices[BRIDGE]["type"] == "bridge_v2"
        # The ones the bridge reports in any other way than connected are all there, heard by the sniffer or not.
        assert {ieee: d["status"] for ieee, d in devices.items() if d["status"] != "connected"} == {
            STRIP: "unidirectional_incoming", BEDROOM_LAMP: "connectivity_issue", DIMMER: "disconnected"}
        assert hub.heard == {}
        ws = await client.ws_connect(f"/ws?token={origin['X-ZLM-Token']}", headers=origin)
        hello = await ws.receive_json()
        assert hello["hue"]["devices"] == devices and hello["hue"]["configured"] is True and hello["hue"]["name"] == "Hue Bridge"
        await ws.close()

    run(scenario, tmp_path, monkeypatch)


def test_hue_enrich_names_kept_in_lists_win_and_lists_stay_untouched(tmp_path, monkeypatch):
    async def scenario(client, hub, origin, bridge):
        api = Api(client, origin)
        home = hub.store.create("Home")
        hub.store.set_device(home, LAMP, {"name": "My own name"})
        saved = json.dumps(hub.store.describe(), sort_keys=True)
        ws = await client.ws_connect(f"/ws?token={origin['X-ZLM-Token']}", headers=origin)
        assert (await ws.receive_json())["names"] == {LAMP: {"name": "My own name"}}
        await set_up(api, bridge)
        names = hub.hello()["names"]
        assert names[LAMP] == {"name": "My own name"}                # a list name always wins
        assert names[STRIP] == {"name": "Kitchen strip"} and names[DIMMER] == {"name": "Bedroom dimmer"}   # no list name: the bridge's
        assert json.dumps(hub.store.describe(), sort_keys=True) == saved   # nothing was written into the lists
        assert len(list((tmp_path / "lists").glob("*.json"))) == 1
        hub.store.update(home, enabled=False)                        # a list that is switched off does not count
        assert hub.hello()["names"][LAMP] == {"name": "Kitchen lamp"}
        await ws.close()

    run(scenario, tmp_path, monkeypatch)


def test_hue_enrich_pages_are_told_when_something_changes(tmp_path, monkeypatch):
    async def scenario(client, hub, origin, bridge):
        api = Api(client, origin)
        await set_up(api, bridge)
        ws = await client.ws_connect(f"/ws?token={origin['X-ZLM-Token']}", headers=origin)
        for _ in range(3):
            await ws.receive_json()                                  # hello, status, backlog
        bridge.set_status(LAMP, "disconnected")
        await api("POST", "/api/hue/refresh")
        kinds = {}
        for text in await drain(ws):
            message = json.loads(text)
            kinds[message["type"]] = message
        assert kinds["hue"]["devices"][LAMP]["status"] == "disconnected" and kinds["hue"]["lastRead"]
        assert "key" not in kinds["hue"] and kinds["names"]["names"][LAMP] == {"name": "Kitchen lamp"}
        await api("DELETE", "/api/hue")
        assert [json.loads(t) for t in await drain(ws)][-1] == {"type": "hue", **hub.hue.view()}   # forgetting reaches the pages too
        assert hub.hue.view()["configured"] is False
        await ws.close()

    run(scenario, tmp_path, monkeypatch)


def test_hue_enrich_a_saved_bridge_is_read_again_at_start_up(tmp_path, monkeypatch):
    async def scenario(client, hub, origin, bridge):
        await set_up(Api(client, origin), bridge)
        later = HueService(tmp_path)
        assert later.configured and later.devices == {}              # nothing is read just by loading the file
        before = len(bridge.requests)
        later.start()
        await until(lambda: later.devices)
        assert len(bridge.requests) > before and later.last_read
        await later.stop()

    run(scenario, tmp_path, monkeypatch)


def test_hue_enrich_devices_without_a_radio_address_or_with_dangling_references_are_skipped_not_fatal():
    resources = {
        "device": {"data": [{"id": "d1", "metadata": {"name": "Tap"}, "services": [{"rid": "gone", "rtype": "button"}]},
                            {"id": "d2", "metadata": {"name": "Lamp", "archetype": "sultan_bulb"}, "services": [{"rid": "z2", "rtype": "zigbee_connectivity"}],
                             "product_data": {"model_id": "M1"}},
                            {"metadata": {"name": "No id"}}, "nonsense"]},
        "zigbee_connectivity": {"data": [{"owner": {"rid": "d2"}, "status": "connected", "mac_address": "00:11:22:33:44:55:66:77"},
                                         {"owner": {"rid": "d3"}, "status": "connected", "mac_address": "00:11:22:33:44:55:66:88"},
                                         {"owner": {"rid": "d1"}, "mac_address": "not an address"}]},
        "room": {"data": [{"metadata": {"name": "Hall"}, "children": [{"rid": "d2"}, {"rid": "nowhere"}]}]},
        "device_power": {"data": [{"owner": {"rid": "d2"}, "power_state": {"battery_level": "n/a"}}]},
    }
    assert hue.build_devices(resources) == {"00:11:22:33:44:55:66:77": {
        "name": "Lamp", "product": None, "model": "M1", "maker": None, "type": "sultan_bulb", "room": "Hall", "status": "connected", "battery": None}}


def test_hue_enrich_the_channel_of_the_bridge_network_comes_from_its_own_entry():
    def entry(channel):
        return {"zigbee_connectivity": {"data": [{"owner": {"rid": "b"}, "mac_address": "00:11:22:33:44:55:66:77", "channel": channel},
                                                 {"owner": {"rid": "d"}, "mac_address": "00:11:22:33:44:55:66:88"}]}}
    assert hue.bridge_channel(entry({"status": "set", "value": "channel_20"})) == 20
    assert hue.bridge_channel(entry({"status": "changing", "value": "channel_11"})) == 11
    for odd in (None, {}, {"value": "channel_99"}, {"value": "channel_x"}, {"value": 20}, {"value": "20"}, "channel_20", []):
        assert hue.bridge_channel(entry(odd)) is None, odd
    assert hue.bridge_channel({}) is None and hue.bridge_channel({"zigbee_connectivity": {"data": "nope"}}) is None


def test_hue_enrich_pages_receive_the_channel_as_a_number_or_null(tmp_path, monkeypatch):
    async def scenario(client, hub, origin, bridge):
        api = Api(client, origin)
        assert (await api("GET", "/api/hue"))[1]["channel"] is None            # nothing known before a bridge is set up
        body = await set_up(api, bridge)
        assert body["channel"] == 25 and hub.hue.view()["channel"] == 25       # the fixture's bridge entry says channel_25
        ws = await client.ws_connect(f"/ws?token={origin['X-ZLM-Token']}", headers=origin)
        assert (await ws.receive_json())["hue"]["channel"] == 25
        await ws.close()
        for row in bridge.resources["zigbee_connectivity"]["data"]:
            row.pop("channel", None)                                           # the bridge stops saying
        await api("POST", "/api/hue/refresh")
        assert hub.hue.status()["channel"] is None

    run(scenario, tmp_path, monkeypatch)


# ------------------------------------------------------------------------------------------ idle

def test_hue_idle_nothing_is_contacted_until_the_user_acts(tmp_path, monkeypatch):
    monkeypatch.setattr(hue, "fetch_certificate", boom)
    monkeypatch.setattr(hue, "browse_mdns", boom)

    async def scenario(client, hub, origin, bridge):
        for path in ("/", "/devices", "/static/common.js", "/locales/fr.json", "/api/lists", "/api/hue"):
            assert (await client.get(path)).status == 200
        ws = await client.ws_connect(f"/ws?token={origin['X-ZLM-Token']}", headers=origin)
        hello = await ws.receive_json()
        assert hello["hue"]["configured"] is False and hello["hue"]["devices"] == {} and hello["names"] == {}
        await asyncio.sleep(0.3)
        assert bridge.requests == [] and hub.hue._tasks == []        # no timer is running either
        await ws.close()

    run(scenario, tmp_path, monkeypatch)
    assert DIALLED == [] and not (tmp_path / "hue.json").exists()


def test_hue_idle_demo_mode_starts_without_any_bridge_call(tmp_path, monkeypatch):
    from zigbee_live_map import server

    monkeypatch.setattr(hue, "fetch_certificate", boom)
    monkeypatch.setattr(hue, "browse_mdns", boom)
    args = types.SimpleNamespace(demo=True, replay=None, data_dir=str(tmp_path), channel=11, focus=None, backlog=100, speed=1.0, pcap=None, port=0, open=False)

    async def main():
        task = asyncio.create_task(server.serve(args))
        await asyncio.sleep(0.5)
        assert not task.done()                                      # it is up, and boom() was never called
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(main())
    assert DIALLED == [] and not (tmp_path / "hue.json").exists()


def test_hue_idle_refuses_addresses_that_are_not_on_the_local_network(tmp_path, monkeypatch):
    monkeypatch.setattr(hue, "fetch_certificate", boom)              # refused before anything is dialled

    async def scenario(client, hub, origin, bridge):
        api = Api(client, origin)
        for host in ("93.184.216.34", "93.184.216.34:8443", "8.8.8.8", "[2001:4860:4860::8888]:443", "::ffff:8.8.8.8", "0.0.0.0", "224.0.0.251",
                     "100.64.0.1", "http://10.0.0.5/x", "10.0.0.5/x", "a b", "", "10.0.0.5:99999", "10.0.0.5:0"):
            for path, body in (("/api/hue/pair", {"host": host}), ("/api/hue/key", {"host": host, "key": bridge.app_key})):
                status, answer = await api("POST", path, body)
                assert status == 400 and answer["error"], (host, path)
        # A name is resolved first, and one that gives no local address is refused.
        for answers in (["93.184.216.34"], ["2001:4860:4860::8888", "93.184.216.34"]):
            async def resolved(host, port, answers=answers):
                return answers
            monkeypatch.setattr(hue, "resolve", resolved)
            assert (await api("POST", "/api/hue/pair", {"host": "bridge.example"}))[0] == 400
        assert not hub.hue.configured and hub.hue.pairing is None and DIALLED == []   # nothing was even dialled

    run(scenario, tmp_path, monkeypatch)


def test_hue_idle_a_name_with_public_and_local_addresses_dials_only_a_local_one(monkeypatch):
    """Seen on a real network: the bridge's .local name gives a public IPv6 address next to its private ones."""
    async def resolved(host, port):
        return ["2001:4860:4860::8888", "fd00::17", "192.168.1.17"]
    monkeypatch.setattr(hue, "resolve", resolved)
    assert asyncio.run(hue.target_address("bridge.local", 443)) == "192.168.1.17"   # IPv4 first, never the public one

    async def resolved_v6(host, port):
        return ["2001:4860:4860::8888", "fd00::17"]
    monkeypatch.setattr(hue, "resolve", resolved_v6)
    assert asyncio.run(hue.target_address("bridge.local", 443)) == "fd00::17"
    with pytest.raises(hue.HueError):
        asyncio.run(hue.target_address("8.8.8.8", 443))


def test_hue_idle_the_address_check_lets_the_local_network_through():
    for address in ("127.0.0.1", "10.1.2.3", "172.16.0.9", "192.168.1.20", "169.254.3.4", "::1", "fe80::1", "fd00::5"):
        assert hue.check_address(address) == address
    for address in ("8.8.8.8", "2001:4860:4860::8888", "::ffff:8.8.8.8", "0.0.0.0", "224.0.0.251", "not an address"):
        with pytest.raises(hue.HueError):
            hue.check_address(address)
