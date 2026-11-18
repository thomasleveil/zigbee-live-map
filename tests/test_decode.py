from zigbee_live_map import crypto, decode

NET = bytes.fromhex("0f1e2d3c4b5a69788796a5b4c3d2e1f0")
COORD64, DEV64 = 0x00124b00_1a2b3c4d, 0x00158d00_01a2b3c4


def test_recover_network_key_from_a_default_key_join():
    frame = decode.build_transport_key(crypto.DEFAULT_TC_LINK_KEY, seq=1, pan=0x1a62, mac_dst=0xcd4a,
                                       mac_src=0x0000, coord64=COORD64, counter=0, network_key=NET)
    assert decode.recover_network_key(frame) == NET
    assert decode.recover_network_key(frame, bytes(16)) is None   # wrong link key: no recovery


def test_a_join_with_a_unique_link_key_is_not_recoverable():
    unique = bytes.fromhex("0102030405060708090a0b0c0d0e0f10")
    frame = decode.build_transport_key(unique, seq=1, pan=0x1a62, mac_dst=0xcd4a, mac_src=0x0000,
                                       coord64=COORD64, counter=0, network_key=NET)
    assert decode.recover_network_key(frame) is None   # the default-key test correctly says "not vulnerable"


def test_identify_reads_manufacturer_and_model_from_decrypted_basic():
    payload = decode.zcl_basic_response("LUMI", "lumi.weather", power=3)
    frame = decode.build_secured_nwk(NET, seq=5, pan=0x1a62, mac_dst=0x0000, mac_src=0x72f6,
                                     nwk_dst=0x0000, nwk_src=0x72f6, radius=30, nwk_seq=5,
                                     src64=DEV64, counter=42, payload=payload)
    assert decode.identify(frame, NET) == {"manufacturer": "LUMI", "model": "lumi.weather", "power": "battery"}
    assert decode.identify(frame, bytes(16)) is None   # wrong key: nothing


def test_identify_reads_firmware_build_when_present():
    payload = decode.zcl_basic_response("SONOFF", "TRVZB", power=3, sw="500+TZSKT31BS102")
    frame = decode.build_secured_nwk(NET, seq=6, pan=0x1a62, mac_dst=0x0000, mac_src=0x3388,
                                     nwk_dst=0x0000, nwk_src=0x3388, radius=30, nwk_seq=6,
                                     src64=DEV64, counter=50, payload=payload)
    assert decode.identify(frame, NET) == {"manufacturer": "SONOFF", "model": "TRVZB", "power": "battery", "sw": "500+TZSKT31BS102"}


def test_link_costs_are_decoded_per_neighbour():
    frame = decode.build_link_status(NET, pan=0x1a62, src=0x6ca5, src64=DEV64, counter=9,
                                     neighbours=[(0x0000, 1, 1), (0x29e5, 3, 5)])
    assert decode.link_costs(frame, NET) == [
        {"addr": "0x0000", "incoming": 1, "outgoing": 1},
        {"addr": "0x29e5", "incoming": 3, "outgoing": 5},
    ]


def test_battery_is_read_from_a_power_config_report():
    payload = decode.power_config_report(80)
    frame = decode.build_secured_nwk(NET, seq=3, pan=0x1a62, mac_dst=0x0000, mac_src=0x72f6,
                                     nwk_dst=0x0000, nwk_src=0x72f6, radius=30, nwk_seq=3,
                                     src64=DEV64, counter=7, payload=payload)
    assert decode.battery(frame, NET) == {"percent": 80}
    assert decode.battery(frame, bytes(16)) is None     # wrong key: nothing
    assert decode.identify(frame, NET) is None          # a Power Config report is not a Basic one


def test_touchlink_scan_response_yields_transaction_and_response_id():
    frame = decode.build_touchlink_scan_response(seq=1, pan=0x1a62, mac_dst=0x0000, mac_src=0x1234,
                                                 transaction_id=0x12345678, response_id=0x9abcdef0)
    assert decode.touchlink_scan_response(frame) == (0x12345678, 0x9abcdef0)
    # A key-transport frame is not a scan response, and vice versa.
    assert decode.touchlink_key_transport(frame) is None


def test_touchlink_join_recovers_network_key_with_the_master_key():
    # End to end: a Network Join Router request that transported the network key under the ZLL master key
    # is parsed and the key recovered using the response id from the Scan Response of the same transaction.
    tid, rid = 0x12345678, 0x9abcdef0
    scan = decode.build_touchlink_scan_response(seq=1, pan=0x1a62, mac_dst=0x0000, mac_src=0x3344,
                                                transaction_id=tid, response_id=rid)
    _, response_id = decode.touchlink_scan_response(scan)
    join = decode.build_touchlink_network_join(crypto.ZLL_KEY_INDEX_MASTER, seq=2, pan=0x1a62,
                                               mac_dst=0x3344, mac_src=0x0000, transaction_id=tid,
                                               response_id=rid, network_key=NET)
    env = decode.touchlink_key_transport(join)
    assert env["key_index"] == crypto.ZLL_KEY_INDEX_MASTER and env["transaction_id"] == tid
    assert decode.recover_touchlink_network_key(join, response_id) == NET
    # The wrong response id (e.g. no scan response seen) does not recover the real key.
    assert decode.recover_touchlink_network_key(join, 0) != NET


def test_touchlink_join_recovers_network_key_with_the_certification_key():
    tid, rid = 0x0abbccdd, 0x11223344
    join = decode.build_touchlink_network_join(crypto.ZLL_KEY_INDEX_CERTIFICATION, seq=3, pan=0x1a62,
                                               mac_dst=0x5566, mac_src=0x0000, transaction_id=tid,
                                               response_id=rid, network_key=NET,
                                               command=decode.ZLL_CMD_NETWORK_START_REQUEST)
    assert decode.recover_touchlink_network_key(join, rid) == NET


def test_touchlink_recovery_ignores_non_touchlink_frames():
    # An ordinary APS transport-key join is not a Touchlink frame.
    aps_join = decode.build_transport_key(crypto.DEFAULT_TC_LINK_KEY, seq=1, pan=0x1a62, mac_dst=0xcd4a,
                                          mac_src=0x0000, coord64=COORD64, counter=0, network_key=NET)
    assert decode.touchlink_key_transport(aps_join) is None
    assert decode.recover_touchlink_network_key(aps_join, 0x11223344) is None
    # And a Touchlink join is not mistaken for an APS transport-key join.
    join = decode.build_touchlink_network_join(crypto.ZLL_KEY_INDEX_MASTER, seq=2, pan=0x1a62,
                                               mac_dst=0x3344, mac_src=0x0000, transaction_id=1,
                                               response_id=2, network_key=NET)
    assert decode.recover_network_key(join) is None


def test_network_payload_round_trips():
    frame = decode.build_secured_nwk(NET, seq=1, pan=0x1a62, mac_dst=0x0000, mac_src=0x1234,
                                     nwk_dst=0x0000, nwk_src=0x1234, radius=30, nwk_seq=1,
                                     src64=DEV64, counter=1, payload=b"hello aps")
    assert decode.decrypt_network_payload(frame, NET) == b"hello aps"
    assert decode.decrypt_network_payload(frame, bytes(16)) is None


def test_nwk_commands_are_named_with_their_fields():
    cases = {
        "01080a72cb0300": ("route_request", {"dst": "0xcb72", "cost": 3, "m2o": True}),
        "02000ab926f7d903": ("route_reply", {"originator": "0x26b9", "responder": "0xd9f7", "cost": 3}),
        "030c72cb": ("network_status", {"status": 12, "addr": "0xcb72"}),
        "0460": ("leave", {"rejoin": True, "request": True, "children": False}),
        "0502d94eb926": ("route_record", {"relays": ["0x4ed9", "0x26b9"]}),
        "0680": ("rejoin_request", {}),
        "07883300": ("rejoin_response", {"addr": "0x3388", "status": 0}),
        "0b0800": ("ed_timeout_request", {"minutes": 256}),
        "0c0001": ("ed_timeout_response", {"status": 0}),
        "1f00": ("0x1f", {}),
    }
    for raw, (name, detail) in cases.items():
        assert decode.nwk_command(bytes.fromhex(raw)) == {"name": name, "detail": detail}, raw


def test_a_truncated_nwk_command_keeps_its_name_without_guessed_fields():
    assert decode.nwk_command(bytes.fromhex("0300")) == {"name": "network_status", "detail": {}}
    assert decode.nwk_command(bytes.fromhex("0503d94e")) == {"name": "route_record", "detail": {}}
    assert decode.nwk_command(b"") is None


def _lqi_entry(addr, ieee, flags, depth, lqi):
    return bytes(8) + ieee.to_bytes(8, "little") + addr.to_bytes(2, "little") + bytes([flags, 0x02, depth, lqi])


def test_mgmt_lqi_response_lists_neighbours_with_relationship_and_lqi():
    zdo = bytes([7, 0, 3, 0, 2]) + _lqi_entry(0x0000, COORD64, 0x00 | 0x04 | (2 << 4), 0, 117) + _lqi_entry(0x3388, DEV64, 0x02 | (1 << 4), 2, 47)
    table = decode.mgmt_lqi(zdo)
    assert table["total"] == 3 and table["start"] == 0
    assert table["rows"] == [
        {"addr": "0x0000", "ieee": "00:12:4b:00:1a:2b:3c:4d", "type": "coordinator", "rel": "sibling", "depth": 0, "lqi": 117},
        {"addr": "0x3388", "ieee": "00:15:8d:00:01:a2:b3:c4", "type": "end_device", "rel": "child", "depth": 2, "lqi": 47},
    ]
    assert decode.mgmt_lqi(bytes([7, 0x84, 0, 0, 0])) is None      # status "not supported"
    assert decode.mgmt_lqi(zdo[:-3]) is None                        # cut short


def test_aps_header_reads_data_acknowledgements_and_requests():
    data = bytes([0x40, 0x01]) + (0x0402).to_bytes(2, "little") + (0x0104).to_bytes(2, "little") + bytes([0x01, 0x33]) + b"\x18\x01\x0a"
    assert decode.aps_header(data) == {"type": "data", "ack_req": True, "cluster": 0x0402, "profile": 0x0104, "counter": 0x33, "payload": b"\x18\x01\x0a"}
    ack = bytes([0x02, 0x01]) + (0x0402).to_bytes(2, "little") + (0x0104).to_bytes(2, "little") + bytes([0x01, 0x33])
    assert decode.aps_header(ack) == {"type": "ack", "ack_req": False, "cluster": 0x0402, "profile": 0x0104, "counter": 0x33}
    assert decode.aps_header(bytes([0x12, 0x07])) == {"type": "ack", "ack_req": False, "counter": 7}   # acknowledgement of an APS command
    secured = bytes([0x60, 0x01]) + (0x0006).to_bytes(2, "little") + (0x0104).to_bytes(2, "little") + bytes([0x01, 0x09]) + bytes(10)
    assert "payload" not in decode.aps_header(secured)               # link-key secured: header only
    assert decode.aps_header(bytes([0x00, 0x01, 0x02])) is None      # truncated
