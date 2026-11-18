import asyncio

from aiohttp.test_utils import TestClient, TestServer

from zigbee_live_map import builders, crypto, decode, server
from zigbee_live_map.devices import DeviceStore
from zigbee_live_map.server import Hub, build_app
from zigbee_live_map.vendors import Registry

IEEE = "00:12:4b:00:00:00:00:01"
NET = bytes.fromhex("0f1e2d3c4b5a69788796a5b4c3d2e1f0")
COORD64, DEV64 = 0x00124B00_1A2B3C4D, 0x00158D00_01A2B3C4


def run(scenario, tmp_path):
    async def main():
        hub = Hub(DeviceStore(tmp_path), Registry(tmp_path), {"channel": None, "mode": "replay", "focus": None, "can_tune": False}, 100)
        async with TestClient(TestServer(build_app(hub), host="127.0.0.1")) as client:
            token = (await (await client.get("/api/session")).json())["token"]
            origin = {"Origin": f"http://127.0.0.1:{client.server.port}", "X-ZLM-Token": token}
            await scenario(client, hub, origin)

    asyncio.run(main())


def test_pages_texts_and_static_files_are_served(tmp_path):
    async def scenario(client, hub, origin):
        for path in ("/", "/devices", "/static/common.js", "/static/common.css", "/locales/fr.json"):
            assert (await client.get(path)).status == 200, path
        codes = [item["code"] for item in await (await client.get("/locales")).json()]
        assert "en" in codes and "fr" in codes
        for path in ("/static/..%2Fserver.py", "/static/index.html", "/locales/..%2F..%2Fserver.json", "/locales/zz.json"):
            assert (await client.get(path)).status == 404, path

    run(scenario, tmp_path)


def test_page_resources_load_whatever_origin_header_the_browser_adds(tmp_path):
    """Some browsers and extensions attach an Origin header to plain same-page resources."""
    async def scenario(client, hub, origin):
        for header in ({"Origin": "null"}, {"Origin": "http://something.else"}, origin, {}):
            for path in ("/", "/devices", "/static/common.css", "/static/common.js", "/locales", "/locales/en.json", "/api/lists", "/api/vendors"):
                assert (await client.get(path, headers=header)).status == 200, (path, header)

    run(scenario, tmp_path)


def test_changes_work_when_the_browser_rewrites_the_origin_header(tmp_path):
    """Seen in the field: a browser sending "http://127.0.0.1" with the port dropped."""
    async def scenario(client, hub, origin):
        token = origin["X-ZLM-Token"]
        for rewritten in ("http://127.0.0.1", "http://localhost", "http://127.0.0.1:1"):
            made = await client.post("/api/lists", json={"name": rewritten}, headers={"Origin": rewritten, "X-ZLM-Token": token})
            assert made.status == 200, rewritten
        ws = await client.ws_connect(f"/ws?token={token}", headers={"Origin": "http://127.0.0.1"})
        assert (await ws.receive_json())["type"] == "hello"
        await ws.close()

    run(scenario, tmp_path)


def test_other_sites_cannot_read_or_change_anything(tmp_path):
    async def scenario(client, hub, origin):
        evil = {"Origin": "http://evil.example"}
        token = origin["X-ZLM-Token"]
        assert (await client.get("/api/lists", headers={"Host": "evil.example"})).status == 403  # DNS rebinding
        assert (await client.post("/api/lists", json={"name": "x"}, headers=evil)).status == 403
        assert (await client.post("/api/lists", json={"name": "x"}, headers={**evil, "X-ZLM-Token": token})).status == 403  # even with a token
        assert (await client.post("/api/lists", json={"name": "x"})).status == 403  # no token: not our page
        assert (await client.post("/api/lists", json={"name": "x"}, headers={"X-ZLM-Token": "guess"})).status == 403
        assert (await client.get("/ws")).status == 403
        assert (await client.get("/ws", headers=evil)).status == 403
        assert (await client.get(f"/ws?token={token}", headers=evil)).status == 403
        read = await client.get("/api/lists", headers=evil)  # sent, but the browser will not let that site see it
        assert not any(name.lower().startswith("access-control-") for name in read.headers)
        assert hub.store.describe() == []

    run(scenario, tmp_path)


def test_device_lists_api(tmp_path):
    async def scenario(client, hub, origin):
        list_id = (await (await client.post("/api/lists", json={"name": "Home"}, headers=origin)).json())["id"]
        base = f"/api/lists/{list_id}"
        assert (await client.put(f"{base}/devices/{IEEE}", json={"name": "Stick", "nwk": "0"}, headers=origin)).status == 200
        bad = await client.put(f"{base}/devices/nope", json={"name": "x"}, headers=origin)
        assert bad.status == 400 and "IEEE" in (await bad.json())["error"]
        state = await (await client.get("/api/lists")).json()
        assert state["lists"][0]["devices"] == {IEEE: {"name": "Stick", "nwk": "0x0000"}}
        assert state["vendors"] == {IEEE: "Texas Instruments"} and state["persistent"] is True
        imported = await client.post(f"{base}/import", data="name,ieee\nPlug,00:11:22:33:44:55:66:02\n", headers=origin)
        assert (await imported.json()) == {"imported": 1}
        export = await client.get(f"{base}/export?format=csv")
        assert "attachment" in export.headers["Content-Disposition"] and "Plug" in await export.text()
        assert (await client.patch(base, json={"enabled": False}, headers=origin)).status == 200
        assert hub.store.merged() == {}
        assert (await client.delete(f"{base}/devices/{IEEE}", headers=origin)).status == 200
        assert (await client.delete(base, headers=origin)).status == 200
        assert (await client.delete(base, headers=origin)).status == 400

    run(scenario, tmp_path)


def test_map_pages_learn_names_and_chip_makers_over_the_websocket(tmp_path):
    async def scenario(client, hub, origin):
        ws = await client.ws_connect(f"/ws?token={origin['X-ZLM-Token']}", headers=origin)
        hello = await ws.receive_json()
        assert hello["type"] == "hello" and hello["names"] == {} and hello["vendors"] == {}
        await ws.receive_json()  # status
        await ws.receive_json()  # backlog
        await ws.send_json({"type": "rename", "ieee": IEEE, "name": "Stick"})
        update = await ws.receive_json()
        assert update == {"type": "names", "names": {IEEE: {"name": "Stick"}}, "vendors": {IEEE: "Texas Instruments"}}
        assert hub.store.describe()[0]["name"] == "My devices"
        await ws.close()

    run(scenario, tmp_path)


def test_network_keys_are_saved_listed_guarded_and_deleted(tmp_path):
    async def scenario(client, hub, origin):
        assert (await client.put("/api/keys/0x1a62", json={"key": "nothex"}, headers=origin)).status == 400
        link = await client.put("/api/keys/0x1a62", json={"key": crypto.DEFAULT_TC_LINK_KEY.hex()}, headers=origin)
        assert link.status == 400 and "link key" in (await link.json())["error"]   # a link key is refused
        assert (await client.put("/api/keys/0x1a62", json={"key": NET.hex()})).status == 403  # no token: not our page
        ok = await client.put("/api/keys/0x1a62", json={"key": NET.hex(), "label": "Home"}, headers=origin)
        assert (await ok.json())["keys"] == [{"pan": "0x1a62", "label": "Home", "key": NET.hex()}]
        assert hub.keys.get("0x1a62") == NET
        assert (await (await client.get("/api/keys")).json())["keys"][0]["pan"] == "0x1a62"
        gone = await (await client.delete("/api/keys/0x1a62", headers=origin)).json()
        assert gone["keys"] == [] and hub.keys.get("0x1a62") is None

    run(scenario, tmp_path)


def test_a_saved_key_auto_applies_when_its_network_is_heard(tmp_path):
    async def scenario(client, hub, origin):
        hub.keys.set("0x1a62", NET.hex(), "Home")
        frame = builders.build_link_status(NET, pan=0x1A62, src=0x6CA5, src64=DEV64, counter=1, neighbours=[(0x0000, 1, 1)])
        await hub.publish(frame, 1.0, None)
        assert hub.pan == "0x1a62"
        assert hub.network_key == NET and hub.key_source == "saved"
        assert hub.link_quality["0x6ca5"] == [{"addr": "0x0000", "incoming": 1, "outgoing": 1}]

    run(scenario, tmp_path)


def test_a_default_key_join_is_flagged_and_the_key_is_recovered(tmp_path):
    async def scenario(client, hub, origin):
        frame = builders.build_transport_key(crypto.DEFAULT_TC_LINK_KEY, seq=1, pan=0x1A62, mac_dst=0xCD4A,
                                           mac_src=0x0000, coord64=COORD64, counter=0, network_key=NET)
        await hub.publish(frame, 1.0, None)
        assert hub.vulnerable is True
        assert hub.network_key == NET and hub.key_source == "recovered"
        assert hub.security_state()["key"] == NET.hex()

    run(scenario, tmp_path)


def test_a_touchlink_join_recovers_the_network_key_after_its_scan_response(tmp_path):
    async def scenario(client, hub, origin):
        tid, rid = 0x12345678, 0x9ABCDEF0
        scan = builders.build_touchlink_scan_response(seq=1, pan=0x1A62, mac_dst=0x0000, mac_src=0x3344,
                                                    transaction_id=tid, response_id=rid)
        join = builders.build_touchlink_network_join(crypto.ZLL_KEY_INDEX_MASTER, seq=2, pan=0x1A62,
                                                   mac_dst=0x3344, mac_src=0x0000, transaction_id=tid,
                                                   response_id=rid, network_key=NET)
        await hub.publish(scan, 1.0, None)
        assert hub.network_key is None   # the scan response alone is not enough
        await hub.publish(join, 2.0, None)
        assert hub.network_key == NET and hub.key_source == "touchlink"
        assert hub.touchlink_recovered is True and hub.vulnerable is False   # distinct from the default-link-key verdict
        assert hub.security_state()["touchlinkRecovered"] is True

    run(scenario, tmp_path)


def test_a_touchlink_join_without_its_scan_response_recovers_nothing(tmp_path):
    async def scenario(client, hub, origin):
        join = builders.build_touchlink_network_join(crypto.ZLL_KEY_INDEX_MASTER, seq=2, pan=0x1A62,
                                                   mac_dst=0x3344, mac_src=0x0000, transaction_id=0x1111,
                                                   response_id=0x2222, network_key=NET)
        await hub.publish(join, 1.0, None)
        assert hub.network_key is None and hub.touchlink_recovered is False

    run(scenario, tmp_path)


def test_a_non_default_join_is_seen_but_not_flagged(tmp_path):
    async def scenario(client, hub, origin):
        unique = bytes.fromhex("0102030405060708090a0b0c0d0e0f10")
        frame = builders.build_transport_key(unique, seq=1, pan=0x1A62, mac_dst=0xCD4A, mac_src=0x0000,
                                           coord64=COORD64, counter=0, network_key=NET)
        await hub.publish(frame, 1.0, None)
        assert hub.vulnerable is False and hub.secure_join_seen is True and hub.network_key is None

    run(scenario, tmp_path)


def test_identity_and_link_costs_are_read_once_a_key_is_known(tmp_path):
    async def scenario(client, hub, origin):
        hub.network_key = NET
        basic = builders.zcl_basic_response("LUMI", "lumi.weather", power=3)
        frame = builders.build_secured_nwk(NET, seq=5, pan=0x1A62, mac_dst=0x0000, mac_src=0x72F6,
                                         nwk_dst=0x0000, nwk_src=0x72F6, radius=30, nwk_seq=5,
                                         src64=DEV64, counter=42, payload=basic)
        await hub.publish(frame, 1.0, None)
        assert hub.identities["0x72f6"] == {"manufacturer": "LUMI", "model": "lumi.weather", "power": "battery"}
        status = builders.build_link_status(NET, pan=0x1A62, src=0x6CA5, src64=DEV64, counter=9,
                                          neighbours=[(0x0000, 1, 1), (0x29E5, 3, 5)])
        await hub.publish(status, 2.0, None)
        assert hub.link_quality["0x6ca5"] == [{"addr": "0x0000", "incoming": 1, "outgoing": 1},
                                              {"addr": "0x29e5", "incoming": 3, "outgoing": 5}]
        batt = builders.build_secured_nwk(NET, seq=6, pan=0x1A62, mac_dst=0x0000, mac_src=0x72F6,
                                        nwk_dst=0x0000, nwk_src=0x72F6, radius=30, nwk_seq=6,
                                        src64=DEV64, counter=43, payload=builders.power_config_report(60))
        await hub.publish(batt, 3.0, None)
        assert hub.batteries["0x72f6"] == {"percent": 60}

    run(scenario, tmp_path)


def _hear(hub, ieee, short, identity=None):
    hub.heard[ieee] = short
    if identity is not None:
        hub.identities[short] = identity


def test_fill_adds_every_identified_heard_device_with_its_model(tmp_path):
    async def scenario(client, hub, origin):
        hub.network_key = NET
        basic = builders.zcl_basic_response("LUMI", "lumi.weather", power=3)
        frame = builders.build_secured_nwk(NET, seq=5, pan=0x1A62, mac_dst=0x0000, mac_src=0x72F6,
                                         nwk_dst=0x0000, nwk_src=0x72F6, radius=30, nwk_seq=5,
                                         src64=DEV64, counter=42, payload=basic)
        await hub.publish(frame, 1.0, None)   # read from the air, not planted
        _hear(hub, "00:11:22:33:44:55:66:09", "0x0009")   # heard, but its identity was never decrypted
        list_id = (await (await client.post("/api/lists", json={"name": "Home"}, headers=origin)).json())["id"]
        ws = await client.ws_connect(f"/ws?token={origin['X-ZLM-Token']}", headers=origin)
        for _ in range(3):
            await ws.receive_json()   # hello, status, backlog
        done = await client.post(f"/api/lists/{list_id}/fill-identities", headers=origin)
        assert done.status == 200 and (await done.json()) == {"added": 1}
        ieee = ":".join(f"{DEV64:016x}"[i:i + 2] for i in range(0, 16, 2))   # the address the frames above were built with
        assert hub.store.lists[list_id]["devices"] == {ieee: {"name": "lumi.weather", "model": "lumi.weather", "nwk": "0x72f6"}}
        update = await ws.receive_json()
        assert update["type"] == "names" and update["names"][ieee]["name"] == "lumi.weather"
        again = await client.post(f"/api/lists/{list_id}/fill-identities", headers=origin)
        assert (await again.json()) == {"added": 0}
        assert (await client.post("/api/lists/nope/fill-identities", headers=origin)).status == 400
        await ws.close()

    run(scenario, tmp_path)


def test_fill_never_overwrites_or_duplicates_a_device_already_named(tmp_path):
    async def scenario(client, hub, origin):
        a, b, c = "00:11:22:33:44:55:66:0a", "00:11:22:33:44:55:66:0b", "00:11:22:33:44:55:66:0c"
        for ieee, short in ((a, "0x000a"), (b, "0x000b"), (c, "0x000c")):
            _hear(hub, ieee, short, {"manufacturer": "ACME", "model": f"model-{short}"})
        home = (await (await client.post("/api/lists", json={"name": "Home"}, headers=origin)).json())["id"]
        office = (await (await client.post("/api/lists", json={"name": "Office"}, headers=origin)).json())["id"]
        hub.store.set_device(home, a, {"name": "Kitchen plug", "model": "mine"})
        hub.store.set_device(office, b, {"name": "Desk lamp"})
        hub.store.update(office, enabled=False)   # a switched-off list still counts as knowing the device
        done = await client.post(f"/api/lists/{home}/fill-identities", headers=origin)
        assert (await done.json()) == {"added": 1}
        assert hub.store.lists[home]["devices"] == {a: {"name": "Kitchen plug", "model": "mine"},
                                                     c: {"name": "model-0x000c", "model": "model-0x000c", "nwk": "0x000c"}}
        assert hub.store.lists[office]["devices"] == {b: {"name": "Desk lamp"}}

    run(scenario, tmp_path)


def test_fill_gives_two_devices_of_one_model_distinct_and_stable_names(tmp_path):
    async def scenario(client, hub, origin):
        a, b, c = "00:11:22:33:44:55:aa:01", "00:11:22:33:44:55:bb:02", "00:11:22:33:44:55:cc:03"
        plug = {"manufacturer": "ACME", "model": "Smart plug"}
        _hear(hub, a, "0x0001", plug)
        _hear(hub, b, "0x0002", plug)
        _hear(hub, c, "0x0003", {"manufacturer": "ACME", "model": "Motion sensor"})
        home = (await (await client.post("/api/lists", json={"name": "Home"}, headers=origin)).json())["id"]
        await client.post(f"/api/lists/{home}/fill-identities", headers=origin)
        names = {ieee: entry["name"] for ieee, entry in hub.store.lists[home]["devices"].items()}
        assert names == {a: "Smart plug aa01", b: "Smart plug bb02", c: "Motion sensor"}
        # Heard in the other order, in a fresh list: the same device gets the same name.
        hub.heard.clear()
        _hear(hub, b, "0x0002", plug)
        _hear(hub, a, "0x0001", plug)
        other = (await (await client.post("/api/lists", json={"name": "Other"}, headers=origin)).json())["id"]
        hub.store.delete(home)
        await client.post(f"/api/lists/{other}/fill-identities", headers=origin)
        assert {ieee: e["name"] for ieee, e in hub.store.lists[other]["devices"].items()} == {a: "Smart plug aa01", b: "Smart plug bb02"}
        # A third plug that turns up later is told apart from the two already named, which keep their names.
        d = "00:11:22:33:44:55:dd:04"
        _hear(hub, d, "0x0004", plug)
        await client.post(f"/api/lists/{other}/fill-identities", headers=origin)
        assert hub.store.lists[other]["devices"][d]["name"] == "Smart plug dd04"
        assert hub.store.lists[other]["devices"][a]["name"] == "Smart plug aa01"

    run(scenario, tmp_path)


def test_fill_state_says_why_there_is_nothing_to_fill(tmp_path):
    async def scenario(client, hub, origin):
        a = "00:11:22:33:44:55:66:0a"
        _hear(hub, a, "0x000a")
        state = await (await client.get("/api/lists")).json()
        assert state["keyKnown"] is False and state["identified"] == 0 and state["fillable"] == 0
        hub.network_key = NET
        state = await (await client.get("/api/lists")).json()
        assert state["keyKnown"] is True and state["identified"] == 0 and state["fillable"] == 0
        hub.identities["0x000a"] = {"manufacturer": "ACME", "model": "Smart plug"}
        state = await (await client.get("/api/lists")).json()
        assert state["identified"] == 1 and state["fillable"] == 1
        home = (await (await client.post("/api/lists", json={"name": "Home"}, headers=origin)).json())["id"]
        hub.store.set_device(home, a, {"name": "Kitchen plug"})
        state = await (await client.get("/api/lists")).json()
        assert state["identified"] == 1 and state["fillable"] == 0

    run(scenario, tmp_path)


def test_fill_is_guarded_like_every_other_change(tmp_path):
    async def scenario(client, hub, origin):
        _hear(hub, "00:11:22:33:44:55:66:0a", "0x000a", {"model": "Smart plug"})
        home = (await (await client.post("/api/lists", json={"name": "Home"}, headers=origin)).json())["id"]
        url, token = f"/api/lists/{home}/fill-identities", origin["X-ZLM-Token"]
        assert (await client.post(url)).status == 403
        assert (await client.post(url, headers={"X-ZLM-Token": "guess"})).status == 403
        assert (await client.post(url, headers={"Origin": "http://evil.example", "X-ZLM-Token": token})).status == 403
        assert (await client.post(url, headers={"Host": "evil.example", "X-ZLM-Token": token})).status == 403
        assert hub.store.lists[home]["devices"] == {}
        ok = await client.post(url, headers=origin)   # the same call from this tool's own page does work
        assert ok.status == 200 and (await ok.json()) == {"added": 1}

    run(scenario, tmp_path)


def test_hello_carries_the_build_of_the_pages(tmp_path):
    async def scenario(client, hub, origin):
        ws = await client.ws_connect(f"/ws?token={origin['X-ZLM-Token']}", headers=origin)
        hello = await ws.receive_json()
        assert hello["build"] == server.page_build() and len(hello["build"]) == 16
        await ws.close()
    run(scenario, tmp_path)


def test_page_build_follows_the_page_files(monkeypatch, tmp_path):
    (tmp_path / "static" / "locales").mkdir(parents=True)
    (tmp_path / "static" / "index.html").write_text("a")
    (tmp_path / "static" / "locales" / "en.json").write_text("{}")
    monkeypatch.setattr(server.resources, "files", lambda _pkg: tmp_path)
    first = server.page_build()
    assert server.page_build() == first
    (tmp_path / "static" / "locales" / "en.json").write_text('{"x": "y"}')
    assert server.page_build() != first


def test_the_network_key_names_network_commands_and_corrects_the_shape_guess(tmp_path):
    async def scenario(client, hub, origin):
        def command(payload, counter):
            return builders.build_secured_nwk(NET, seq=counter, pan=0x1A62, mac_dst=0x0000, mac_src=0x6164,
                                            nwk_dst=0x0000, nwk_src=0x6164, radius=30, nwk_seq=counter,
                                            src64=DEV64, counter=counter, payload=payload, command=True)
        status = command(bytes.fromhex("030c72cb"), 1)   # sent to the coordinator: shaped like a route record
        await hub.publish(status, 1.0, None)
        assert hub.events[-1]["cat"] == "route_record" and "nc" not in hub.events[-1]   # no key: the guess stays
        hub.network_key = NET
        await hub.publish(command(bytes.fromhex("030c72cb"), 2), 2.0, None)
        ev = hub.events[-1]
        assert (ev["cat"], ev["nc"], ev["nx"]) == ("nwk_cmd", "network_status", {"status": 12, "addr": "0xcb72"})
        await hub.publish(command(bytes.fromhex("0501d94e"), 3), 3.0, None)
        ev = hub.events[-1]
        assert (ev["cat"], ev["nc"], ev["nx"]) == ("route_record", "route_record", {"relays": ["0x4ed9"]})
    run(scenario, tmp_path)


def test_neighbour_tables_and_end_to_end_acknowledgements_are_read_with_the_key(tmp_path):
    def secured(payload, src, dst, counter):
        return builders.build_secured_nwk(NET, seq=counter, pan=0x1A62, mac_dst=dst, mac_src=src, nwk_dst=dst, nwk_src=src,
                                        radius=30, nwk_seq=counter, src64=DEV64, counter=counter, payload=payload)

    def entry(addr, flags, lqi):
        return bytes(16) + addr.to_bytes(2, "little") + bytes([flags, 0, 1, lqi])

    async def scenario(client, hub, origin):
        hub.network_key = NET
        zdo = bytes([5, 0, 2, 0, 2]) + entry(0x0000, 0x00 | (2 << 4), 117) + entry(0x3388, 0x02 | (1 << 4), 30)
        lqi = bytes([0x00, 0x00]) + (0x8031).to_bytes(2, "little") + (0x0000).to_bytes(2, "little") + bytes([0x00, 0x10]) + zdo
        await hub.publish(secured(lqi, 0x6CA5, 0x0000, 1), 1.0, None)
        assert [(r["addr"], r["rel"], r["lqi"]) for r in hub.neighbors["0x6ca5"]] == [("0x0000", "sibling", 117), ("0x3388", "child", 30)]
        assert hub.events[-1]["zd"] == "mgmt_lqi"
        req = bytes([0x40, 0x01]) + (0x0402).to_bytes(2, "little") + (0x0104).to_bytes(2, "little") + bytes([0x01, 0x21]) + b"\x18\x01\x0a"
        await hub.publish(secured(req, 0x6CA5, 0x0000, 2), 2.0, None)
        assert (hub.events[-1]["ap"], hub.events[-1]["ac"]) == ("req", 0x21)
        ack = bytes([0x02, 0x01]) + (0x0402).to_bytes(2, "little") + (0x0104).to_bytes(2, "little") + bytes([0x01, 0x21])
        await hub.publish(secured(ack, 0x0000, 0x6CA5, 3), 2.05, None)
        assert (hub.events[-1]["ap"], hub.events[-1]["ac"]) == ("ack", 0x21)
        hello = hub.hello()
        assert hello["neighbors"]["0x6ca5"][1]["lqi"] == 30
    run(scenario, tmp_path)


def test_zcl_requests_and_answers_are_marked_for_pairing(tmp_path):
    def secured(payload, src, dst, counter):
        return builders.build_secured_nwk(NET, seq=counter, pan=0x1A62, mac_dst=dst, mac_src=src, nwk_dst=dst, nwk_src=src,
                                        radius=30, nwk_seq=counter, src64=DEV64, counter=counter, payload=payload)
    head = lambda: (0x0201).to_bytes(2, "little") + (0x0104).to_bytes(2, "little") + bytes([0x01])

    async def scenario(client, hub, origin):
        hub.network_key = NET
        write = bytes([0x00, 0x01]) + head() + bytes([0x05]) + bytes([0x00, 0x06, 0x02, 0x12, 0x00, 0x29, 0xd0, 0x07])
        await hub.publish(secured(write, 0x0000, 0x3388, 1), 1.0, None)
        assert (hub.events[-1]["zs"], hub.events[-1]["zx"]) == ("c6", 1)
        answer = bytes([0x00, 0x01]) + head() + bytes([0x09]) + bytes([0x18, 0x06, 0x04, 0x00])
        await hub.publish(secured(answer, 0x3388, 0x0000, 2), 1.04, None)
        assert hub.events[-1]["zs"] == "c6" and "zx" not in hub.events[-1]
    run(scenario, tmp_path)


def test_a_logged_frame_can_be_opened_layer_by_layer(tmp_path):
    async def scenario(client, hub, origin):
        frame = builders.build_link_status(NET, pan=0x1A62, src=0x6CA5, src64=DEV64, counter=9, neighbours=[(0x0000, 1, 1)])
        await hub.publish(frame, 1.0, None)
        n = hub.events[-1]["n"]
        resp = await client.get(f"/api/frames/{n}", headers=origin)
        body = await resp.json()
        assert resp.status == 200 and body["decrypted"] is False and body["hex"] == frame.hex(" ")
        assert [l["layer"] for l in body["layers"]][-1] == "NWK security"
        hub.network_key = NET
        body = await (await client.get(f"/api/frames/{n}", headers=origin)).json()
        assert body["layers"][-1]["layer"] == "NWK command"
        assert (await client.get("/api/frames/999999", headers=origin)).status == 404
    run(scenario, tmp_path)


def test_a_channel_change_forgets_everything_the_previous_network_revealed(tmp_path):
    class Source:
        tuned = None

        def set_channel(self, channel, generation):
            self.tuned = (channel, generation)

    async def scenario(client, hub, origin):
        hub.source, hub.info["channel"] = Source(), 15
        await hub.use_key(NET, "touchlink")
        hub.vulnerable = hub.secure_join_seen = hub.touchlink_recovered = True
        hub.pan = "0x1a62"
        for table in (hub.identities, hub.link_quality, hub.batteries, hub.neighbors):
            table["0x0001"] = {}
        await hub.tune(20)
        assert hub.source.tuned == (20, 1) and hub.info["channel"] == 20
        assert hub.network_key is None and hub.key_source is None and hub.pan is None
        assert not (hub.vulnerable or hub.secure_join_seen or hub.touchlink_recovered)
        assert not (hub.identities or hub.link_quality or hub.batteries or hub.neighbors)
        assert hub.security_state()["touchlinkRecovered"] is False

    run(scenario, tmp_path)
