from zigbee_live_map import frames as zf

PAN, COORD, ROUTER, CHILD = "0x1a62", "0x0000", "0x2b01", "0x7c01"
ROUTER_IEEE = "02:00:00:ff:fe:00:2b:01"


def nwk(mac_dst, mac_src, **kw):
    defaults = dict(command=False, nwk_dst=mac_dst, nwk_src=mac_src, radius=30, nwk_seq=1, hop_ieee=ROUTER_IEEE)
    return zf.build_nwk(7, PAN, mac_dst, mac_src, **{**defaults, **kw})


def classify(frame):
    return zf.Classifier().event(frame, 0.0)


def test_direct_data_exposes_both_layers_and_the_hop_ieee():
    ev = classify(nwk(COORD, ROUTER))
    assert ev["cat"] == "data_direct"
    assert (ev["ms"], ev["md"], ev["ns"], ev["nd"]) == (ROUTER, COORD, ROUTER, COORD)
    assert ev["pan"] == PAN and ev["r"] == 30 and ev["ieee"] == ROUTER_IEEE


def test_relayed_data_is_multihop():
    ev = classify(nwk(COORD, ROUTER, nwk_src=CHILD, nwk_dst=COORD, radius=29))
    assert ev["cat"] == "data_multihop" and ev["ns"] == CHILD and ev["ms"] == ROUTER


def test_source_route_relays_are_readable():
    ev = classify(nwk(ROUTER, COORD, nwk_dst=CHILD, nwk_src=COORD, relays=[ROUTER]))
    assert ev["cat"] == "data_multihop" and ev["relays"] == [ROUTER]


def test_network_commands_are_classified_by_shape():
    link = classify(nwk("0xffff", ROUTER, command=True, nwk_dst="0xfffc", radius=1))
    flood = classify(nwk("0xffff", COORD, command=True, nwk_dst="0xfffc", nwk_src=COORD, radius=10))
    record = classify(nwk(COORD, ROUTER, command=True, nwk_dst=COORD))
    other = classify(nwk(CHILD, ROUTER, command=True, nwk_dst=CHILD))
    assert [e["cat"] for e in (link, flood, record, other)] == ["link_status", "route_request", "route_record", "nwk_cmd"]


def test_broadcast_data():
    assert classify(nwk("0xffff", COORD, nwk_dst="0xfffd", nwk_src=COORD))["cat"] == "broadcast"


def test_poll_and_its_acknowledgement():
    clf = zf.Classifier()
    poll = clf.event(zf.build_poll(42, PAN, ROUTER, CHILD), 0.0)
    ack = clf.event(zf.build_ack(42), 0.001)
    assert poll["cat"] == "poll" and (poll["ms"], poll["md"]) == (CHILD, ROUTER)
    assert ack["cat"] == "ack" and (ack["ms"], ack["md"]) == (ROUTER, CHILD)


def test_unrelated_ack_stays_anonymous():
    clf = zf.Classifier()
    clf.event(zf.build_poll(42, PAN, ROUTER, CHILD), 0.0)
    assert "ms" not in clf.event(zf.build_ack(43), 0.001)


def test_beacon_capacity_bits():
    full = classify(zf.build_beacon(1, PAN, ROUTER, "02:00:00:00:00:1a:62:00", zr=False, zed=False, permit=False))
    free = classify(zf.build_beacon(1, PAN, ROUTER, "02:00:00:00:00:1a:62:00", zr=True, zed=True, permit=True, depth=2))
    assert full["cat"] == "beacon" and full["bcn"] == {"permit": False, "zr": False, "zed": False, "depth": 1, "epid": "02:00:00:00:00:1a:62:00"}
    assert free["bcn"]["zr"] and free["bcn"]["zed"] and free["bcn"]["permit"] and free["bcn"]["depth"] == 2


def test_beacon_request():
    assert classify(zf.build_beacon_request(3))["cat"] == "beacon_req"


def test_truncated_and_garbage_frames_never_raise():
    good = nwk(COORD, ROUTER)
    for cut in range(len(good)):
        assert zf.Classifier().event(good[:cut], 0.0)["cat"] in {"other", "ack", "data_direct", "data_multihop"}
    assert classify(b"")["cat"] == "other"
    assert classify(bytes(range(40)))["cat"] in {"other", "ack", "mac_cmd"}
