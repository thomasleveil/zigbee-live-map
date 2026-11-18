from zigbee_live_map import builders, wire
from zigbee_live_map import frames as zf

PAN, COORD, ROUTER, CHILD = "0x1a62", "0x0000", "0x2b01", "0x7c01"
ROUTER_IEEE = "02:00:00:ff:fe:00:2b:01"


def nwk(mac_dst, mac_src, **kw):
    defaults = dict(command=False, nwk_dst=mac_dst, nwk_src=mac_src, radius=30, nwk_seq=1, hop_ieee=ROUTER_IEEE)
    return builders.build_nwk(7, PAN, mac_dst, mac_src, **{**defaults, **kw})


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
    poll = clf.event(builders.build_poll(42, PAN, ROUTER, CHILD), 0.0)
    ack = clf.event(builders.build_ack(42), 0.001)
    assert poll["cat"] == "poll" and (poll["ms"], poll["md"]) == (CHILD, ROUTER)
    assert ack["cat"] == "ack" and (ack["ms"], ack["md"]) == (ROUTER, CHILD)


def test_unrelated_ack_stays_anonymous():
    clf = zf.Classifier()
    clf.event(builders.build_poll(42, PAN, ROUTER, CHILD), 0.0)
    assert "ms" not in clf.event(builders.build_ack(43), 0.001)


def test_beacon_capacity_bits():
    full = classify(builders.build_beacon(1, PAN, ROUTER, "02:00:00:00:00:1a:62:00", zr=False, zed=False, permit=False))
    free = classify(builders.build_beacon(1, PAN, ROUTER, "02:00:00:00:00:1a:62:00", zr=True, zed=True, permit=True, depth=2))
    assert full["cat"] == "beacon" and full["bcn"] == {"permit": False, "zr": False, "zed": False, "depth": 1, "epid": "02:00:00:00:00:1a:62:00"}
    assert free["bcn"]["zr"] and free["bcn"]["zed"] and free["bcn"]["permit"] and free["bcn"]["depth"] == 2


def test_beacon_request():
    assert classify(builders.build_beacon_request(3))["cat"] == "beacon_req"


def test_truncated_and_garbage_frames_never_raise():
    good = nwk(COORD, ROUTER)
    for cut in range(len(good)):
        assert zf.Classifier().event(good[:cut], 0.0)["cat"] in {"other", "ack", "no_data", "data_direct", "data_multihop"}
    assert classify(b"")["cat"] == "other"
    assert classify(bytes(range(40)))["cat"] in {"other", "ack", "mac_cmd"}


def test_retransmission_is_the_same_bytes_again():
    clf = zf.Classifier()
    frame = nwk(COORD, ROUTER)
    first, again = clf.event(frame, 10.0), clf.event(frame, 10.004)
    later = clf.event(frame, 12.0)
    other = clf.event(nwk(COORD, ROUTER), 12.001)
    assert "rt" not in first and again["rt"] == 1
    assert "rt" not in later and "rt" not in other


def test_nwk_sequence_number_identifies_a_message_across_hops():
    assert classify(nwk(COORD, ROUTER, nwk_src=CHILD, nwk_seq=77))["q"] == 77


def test_ack_frame_pending_bit():
    assert zf.Classifier().event(builders.build_ack(1, pending=True), 0.0)["fp"] == 1
    assert "fp" not in zf.Classifier().event(builders.build_ack(1), 0.0)


def test_empty_data_frame_after_a_pending_ack_is_a_no_data_reply():
    clf = zf.Classifier()
    clf.event(builders.build_poll(42, PAN, ROUTER, CHILD), 0.0)
    clf.event(builders.build_ack(42, pending=True), 0.001)
    ev = clf.event(builders.build_empty_data(9, PAN, ROUTER, CHILD), 0.005)
    assert ev["cat"] == "no_data" and (ev["ms"], ev["md"], ev["pan"]) == (ROUTER, CHILD, PAN)


def test_inter_pan_frame_has_a_frame_control_only_nwk_header():
    ev = classify(builders.build_inter_pan(5, PAN, ROUTER_IEEE))
    assert ev["cat"] == "inter_pan" and ev["ms"] == ROUTER_IEEE and ev["md"] == "0xffff" and ev["pan"] == PAN
    assert "ns" not in ev


def test_green_power_frame_exposes_its_source_id():
    ev = classify(builders.build_gpdf(3, 0x0151A2B3))
    assert ev["cat"] == "green_power" and ev["gpd"] == "0x0151a2b3"


def test_green_power_with_extended_frame_control():
    frame = bytes([0x01, 0x08, 1]) + bytes.fromhex("ffffffff") + bytes([0x8C, 0x10]) + (0x12345678).to_bytes(4, "little") + bytes(9)
    ev = classify(frame)
    assert ev["cat"] == "green_power" and ev["gpd"] == "0x12345678"


def test_2015_frame_with_suppressed_sequence_number_and_header_ies():
    inner = nwk(COORD, ROUTER)[9:]   # the NWK frame of a 2006 frame
    fcf = 0x0001 | 0x0040 | 0x0100 | 0x0200 | (2 << 10) | (2 << 12) | (2 << 14)   # data, PAN id compression, no seq, IEs
    ie = (2 | (0x1A << 7)).to_bytes(2, "little") + b"\xaa\xbb"   # a 2-byte header IE
    term = (0x7F << 7).to_bytes(2, "little")                       # header termination 2: payload follows
    frame = fcf.to_bytes(2, "little") + builders.short_bytes(PAN) + builders.short_bytes(COORD) + builders.short_bytes(ROUTER) + ie + term + inner
    ev = classify(frame)
    assert ev["cat"] == "data_direct" and (ev["ms"], ev["md"], ev["pan"], ev["ns"]) == (ROUTER, COORD, PAN, ROUTER)


def test_2015_pan_id_compression_table():
    # IEEE 802.15.4-2015 table 7-2: (dst mode, src mode, compression) -> (dst PAN, src PAN)
    assert wire.pan_ids(2, 0, 0, False) == (False, False) and wire.pan_ids(2, 0, 0, True) == (True, False)
    assert wire.pan_ids(2, 2, 0, False) == (True, False) and wire.pan_ids(2, 2, 0, True) == (False, False)
    assert wire.pan_ids(2, 0, 3, False) == (False, True) and wire.pan_ids(2, 0, 3, True) == (False, False)
    assert wire.pan_ids(2, 3, 3, False) == (True, False) and wire.pan_ids(2, 3, 3, True) == (False, False)
    assert wire.pan_ids(2, 2, 2, False) == (True, True) and wire.pan_ids(2, 2, 3, True) == (True, False)


def test_mac_security_and_unused_frame_types_stay_not_decoded():
    assert classify(bytes([0x69, 0x88, 1]) + bytes(20))["cat"] == "other"   # MAC security enabled
    assert classify(bytes([0x04, 0x88, 1]) + bytes(20))["cat"] == "other"   # multipurpose frame


def test_a_frame_is_read_once_whoever_looks_at_it():
    frame = wire.read(nwk(COORD, ROUTER))
    assert wire.read(frame) is frame
    assert (frame.mac.src, frame.mac.dst, frame.mac.pan) == (ROUTER, COORD, PAN)
    assert frame.nwk.start == frame.mac.end == 9 and frame.nwk.aux.end == frame.nwk.end == 31
    assert wire.ieee_text(frame.nwk.aux.src64) == ROUTER_IEEE and frame.nwk.aux.key_id == 1
    assert zf.Classifier().event(frame, 0.0) == zf.Classifier().event(frame.raw, 0.0)
    cut = wire.read(frame.raw[:20])
    assert cut.mac is not None and cut.net is None and isinstance(cut.problem, wire.Truncated)
