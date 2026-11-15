import asyncio
from collections import Counter

from zigbee_live_map import demo
from zigbee_live_map.frames import Classifier


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
