import asyncio
from collections import Counter

from zigbee_live_map import demo
from zigbee_live_map.devices import DeviceStore
from zigbee_live_map.frames import Classifier
from zigbee_live_map.server import Hub
from zigbee_live_map.vendors import Registry


def test_demo_network_produces_a_decodable_realistic_mix():
    events, clf = [], Classifier()

    async def emit(frame, rssi):
        events.append(clf.event(frame, 0.0, rssi))

    async def run():
        task = asyncio.create_task(demo.DemoNetwork(emit, speed=60).run())
        await asyncio.sleep(3)  # three minutes of simulated network
        task.cancel()

    asyncio.run(run())
    cats = Counter(e["cat"] for e in events)
    assert "other" not in cats and "mac_cmd" not in cats
    for expected in ("poll", "ack", "link_status", "data_direct", "data_multihop", "broadcast", "route_request", "route_record", "beacon", "beacon_req"):
        assert cats[expected] > 0, expected
    assert {e["pan"] for e in events if "pan" in e} <= {demo.PAN, "0xffff"}
    acks = [e for e in events if e["cat"] == "ack"]
    assert all("ms" in e for e in acks)  # every acknowledgement is attributed to its hop
    meter = [e["bcn"] for e in events if e["cat"] == "beacon" and e["ms"] in demo.NO_CHILDREN]
    assert meter and not any(b["zr"] or b["zed"] for b in meter)


def test_demo_faults_are_visible_in_the_clear_headers():
    events, clf, clock = [], Classifier(), iter(range(10**9))

    async def emit(frame, rssi):
        events.append(clf.event(frame, next(clock) / 1000, rssi))

    async def run():
        task = asyncio.create_task(demo.DemoNetwork(emit, speed=60).run())
        await asyncio.sleep(3)
        task.cancel()

    asyncio.run(run())
    weak = next(iter(demo.WEAK_LINKS))
    retried = [e for e in events if e.get("rt")]
    assert retried and all({e["ms"], e["md"]} == set(weak) for e in retried)
    sent = [e for e in events if e["cat"] != "ack" and {e.get("ms"), e.get("md")} == set(weak)]
    assert 0.08 < len(retried) / len(sent) < 0.45


def test_demo_security_features_light_up_through_the_hub(tmp_path):
    hub = Hub(DeviceStore(tmp_path), Registry(tmp_path), {"channel": 15, "mode": "demo", "focus": None, "can_tune": False}, 5000)
    clock = iter(range(10 ** 9))

    async def emit(frame, rssi):
        await hub.publish(frame, next(clock) / 1000, rssi)

    async def run():
        task = asyncio.create_task(demo.DemoNetwork(emit, speed=60).run())
        await asyncio.sleep(3)
        task.cancel()

    asyncio.run(run())
    # The default-key join is caught and the (fictional) network key is recovered from the air.
    assert hub.vulnerable is True
    assert hub.network_key == demo.DEMO_NET_KEY and hub.key_source == "recovered"
    # With the key, devices announce their model and routers report their measured link costs.
    assert any(ident.get("model") for ident in hub.identities.values())
    assert hub.link_quality
    worst = max(max(r["incoming"], r["outgoing"]) for rows in hub.link_quality.values() for r in rows)
    assert worst >= 5  # the deliberately weak link shows up as a poor cost the mesh itself measured
    # Battery devices report their level on the Power Configuration cluster.
    percents = [b["percent"] for b in hub.batteries.values() if "percent" in b]
    assert percents and min(percents) <= 15   # the deliberately low battery is caught
