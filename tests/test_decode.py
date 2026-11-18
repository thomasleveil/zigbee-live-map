from zigbee_live_map import builders, crypto, decode
from zigbee_live_map.dissect import dissect


# What the server does with a decrypted frame (Hub._inspect, Hub._recover_touchlink), in one call each.

def identify(frame, key):
    info = decode.device_info(decode.aps_header(decode.decrypt_network_payload(frame, key) or b"") or {})
    return info["identity"] if info else None


def battery(frame, key):
    info = decode.device_info(decode.aps_header(decode.decrypt_network_payload(frame, key) or b"") or {})
    return info["battery"] if info else None


def link_costs(frame, key):
    cmd = decode.nwk_command(decode.decrypt_network_payload(frame, key) or b"")
    return cmd["detail"]["links"] if cmd and cmd["name"] == "link_status" else None


def recover_touchlink_network_key(frame, response_id):
    kt = decode.touchlink_key_transport(frame)
    return crypto.zll_decrypt_network_key(kt["key_index"], kt["transaction_id"], response_id, kt["encrypted_key"]) if kt else None

NET = bytes.fromhex("0f1e2d3c4b5a69788796a5b4c3d2e1f0")
COORD64, DEV64 = 0x00124b00_1a2b3c4d, 0x00158d00_01a2b3c4


def test_recover_network_key_from_a_default_key_join():
    frame = builders.build_transport_key(crypto.DEFAULT_TC_LINK_KEY, seq=1, pan=0x1a62, mac_dst=0xcd4a,
                                       mac_src=0x0000, coord64=COORD64, counter=0, network_key=NET)
    assert decode.recover_network_key(frame) == NET
    assert decode.recover_network_key(frame, bytes(16)) is None   # wrong link key: no recovery


def test_a_join_with_a_unique_link_key_is_not_recoverable():
    unique = bytes.fromhex("0102030405060708090a0b0c0d0e0f10")
    frame = builders.build_transport_key(unique, seq=1, pan=0x1a62, mac_dst=0xcd4a, mac_src=0x0000,
                                       coord64=COORD64, counter=0, network_key=NET)
    assert decode.recover_network_key(frame) is None   # the default-key test correctly says "not vulnerable"


def test_identify_reads_manufacturer_and_model_from_decrypted_basic():
    payload = builders.zcl_basic_response("LUMI", "lumi.weather", power=3)
    frame = builders.build_secured_nwk(NET, seq=5, pan=0x1a62, mac_dst=0x0000, mac_src=0x72f6,
                                     nwk_dst=0x0000, nwk_src=0x72f6, radius=30, nwk_seq=5,
                                     src64=DEV64, counter=42, payload=payload)
    assert identify(frame, NET) == {"manufacturer": "LUMI", "model": "lumi.weather", "power": "battery"}
    assert identify(frame, bytes(16)) is None   # wrong key: nothing


def test_identify_reads_firmware_build_when_present():
    payload = builders.zcl_basic_response("SONOFF", "TRVZB", power=3, sw="500+TZSKT31BS102")
    frame = builders.build_secured_nwk(NET, seq=6, pan=0x1a62, mac_dst=0x0000, mac_src=0x3388,
                                     nwk_dst=0x0000, nwk_src=0x3388, radius=30, nwk_seq=6,
                                     src64=DEV64, counter=50, payload=payload)
    assert identify(frame, NET) == {"manufacturer": "SONOFF", "model": "TRVZB", "power": "battery", "sw": "500+TZSKT31BS102"}


def test_link_costs_are_decoded_per_neighbour():
    frame = builders.build_link_status(NET, pan=0x1a62, src=0x6ca5, src64=DEV64, counter=9,
                                     neighbours=[(0x0000, 1, 1), (0x29e5, 3, 5)])
    assert link_costs(frame, NET) == [
        {"addr": "0x0000", "incoming": 1, "outgoing": 1},
        {"addr": "0x29e5", "incoming": 3, "outgoing": 5},
    ]


def test_battery_is_read_from_a_power_config_report():
    payload = builders.power_config_report(80)
    frame = builders.build_secured_nwk(NET, seq=3, pan=0x1a62, mac_dst=0x0000, mac_src=0x72f6,
                                     nwk_dst=0x0000, nwk_src=0x72f6, radius=30, nwk_seq=3,
                                     src64=DEV64, counter=7, payload=payload)
    assert battery(frame, NET) == {"percent": 80}
    assert battery(frame, bytes(16)) is None     # wrong key: nothing
    assert identify(frame, NET) is None          # a Power Config report is not a Basic one


def test_touchlink_scan_response_yields_transaction_and_response_id():
    frame = builders.build_touchlink_scan_response(seq=1, pan=0x1a62, mac_dst=0x0000, mac_src=0x1234,
                                                 transaction_id=0x12345678, response_id=0x9abcdef0)
    assert decode.touchlink_scan_response(frame) == (0x12345678, 0x9abcdef0)
    # A key-transport frame is not a scan response, and vice versa.
    assert decode.touchlink_key_transport(frame) is None


def test_touchlink_join_recovers_network_key_with_the_master_key():
    # End to end: a Network Join Router request that transported the network key under the ZLL master key
    # is parsed and the key recovered using the response id from the Scan Response of the same transaction.
    tid, rid = 0x12345678, 0x9abcdef0
    scan = builders.build_touchlink_scan_response(seq=1, pan=0x1a62, mac_dst=0x0000, mac_src=0x3344,
                                                transaction_id=tid, response_id=rid)
    _, response_id = decode.touchlink_scan_response(scan)
    join = builders.build_touchlink_network_join(crypto.ZLL_KEY_INDEX_MASTER, seq=2, pan=0x1a62,
                                               mac_dst=0x3344, mac_src=0x0000, transaction_id=tid,
                                               response_id=rid, network_key=NET)
    env = decode.touchlink_key_transport(join)
    assert env["key_index"] == crypto.ZLL_KEY_INDEX_MASTER and env["transaction_id"] == tid
    assert recover_touchlink_network_key(join, response_id) == NET
    # The wrong response id (e.g. no scan response seen) does not recover the real key.
    assert recover_touchlink_network_key(join, 0) != NET


def test_touchlink_join_recovers_network_key_with_the_certification_key():
    tid, rid = 0x0abbccdd, 0x11223344
    join = builders.build_touchlink_network_join(crypto.ZLL_KEY_INDEX_CERTIFICATION, seq=3, pan=0x1a62,
                                               mac_dst=0x5566, mac_src=0x0000, transaction_id=tid,
                                               response_id=rid, network_key=NET,
                                               command=decode.ZLL_CMD_NETWORK_START_REQUEST)
    assert recover_touchlink_network_key(join, rid) == NET


def test_touchlink_recovery_ignores_non_touchlink_frames():
    # An ordinary APS transport-key join is not a Touchlink frame.
    aps_join = builders.build_transport_key(crypto.DEFAULT_TC_LINK_KEY, seq=1, pan=0x1a62, mac_dst=0xcd4a,
                                          mac_src=0x0000, coord64=COORD64, counter=0, network_key=NET)
    assert decode.touchlink_key_transport(aps_join) is None
    assert recover_touchlink_network_key(aps_join, 0x11223344) is None
    # And a Touchlink join is not mistaken for an APS transport-key join.
    join = builders.build_touchlink_network_join(crypto.ZLL_KEY_INDEX_MASTER, seq=2, pan=0x1a62,
                                               mac_dst=0x3344, mac_src=0x0000, transaction_id=1,
                                               response_id=2, network_key=NET)
    assert decode.recover_network_key(join) is None


def test_network_payload_round_trips():
    frame = builders.build_secured_nwk(NET, seq=1, pan=0x1a62, mac_dst=0x0000, mac_src=0x1234,
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


def test_exchange_tells_requests_from_answers():
    def aps(profile, cluster, payload):
        return {"type": "data", "profile": profile, "cluster": cluster, "payload": payload}
    assert decode.exchange(aps(0x0104, 0x0201, bytes([0x00, 0x06, 0x02, 0x12, 0x00, 0x29, 0xd0, 0x07]))) == {"seq": "c6", "expects": True}    # Write Attributes
    assert decode.exchange(aps(0x0104, 0x0201, bytes([0x18, 0x06, 0x04, 0x00]))) == {"seq": "c6", "expects": False}                       # Write Attributes Response
    assert decode.exchange(aps(0x0104, 0x0402, bytes([0x18, 0x09, 0x0a, 0x00, 0x00, 0x29, 0x10, 0x08]))) == {"seq": "c9", "expects": False}  # report, no default response wanted
    assert decode.exchange(aps(0x0104, 0x0006, bytes([0x01, 0x07, 0x01]))) == {"seq": "c7", "expects": True}                              # On, default response wanted
    assert decode.exchange(aps(0x0104, 0xfc11, bytes([0x04, 0x02, 0x11, 0x03, 0x02]))) == {"seq": "c3", "expects": True}                  # manufacturer-specific write
    assert decode.exchange(aps(0x0000, 0x0031, bytes([0x2a, 0x00]))) == {"seq": "d42", "expects": True}                                   # Mgmt_Lqi_req
    assert decode.exchange(aps(0x0000, 0x8031, bytes([0x2a, 0x00, 0, 0, 0]))) == {"seq": "d42", "expects": False}                         # Mgmt_Lqi_rsp
    assert decode.exchange({"type": "ack", "counter": 1}) is None


def test_dissect_reads_every_layer_with_the_key_and_stops_at_security_without_it():
    zcl = bytes([0x18, 0x07, 0x0a, 0x00, 0x00, 0x29, 0x10, 0x08])   # report: attribute 0x0000, int16, 2064
    aps = bytes([0x00, 0x01]) + (0x0402).to_bytes(2, "little") + (0x0104).to_bytes(2, "little") + bytes([0x01, 0x21]) + zcl
    frame = builders.build_secured_nwk(NET, seq=5, pan=0x1a62, mac_dst=0x0000, mac_src=0x72f6, nwk_dst=0x0000, nwk_src=0x72f6,
                                     radius=30, nwk_seq=5, src64=DEV64, counter=42, payload=aps)
    names = lambda layers: [l["layer"] for l in layers]
    field = lambda layers, layer, name: dict(next(l for l in layers if l["layer"] == layer)["fields"])[name]
    keyless = dissect(frame)
    assert names(keyless) == ["IEEE 802.15.4 MAC", "Zigbee NWK", "NWK security"]
    assert field(keyless, "NWK security", "Payload") == "encrypted (no network key)"
    keyed = dissect(frame, NET)
    assert names(keyed) == ["IEEE 802.15.4 MAC", "Zigbee NWK", "NWK security", "APS", "ZCL"]
    assert field(keyed, "APS", "Cluster") == "0x0402 (Temperature Measurement)"
    assert field(keyed, "ZCL", "Command") == "0x0a (Report Attributes)" and field(keyed, "ZCL", "Attributes") == "0x0000 = 2064"
    assert names(dissect(frame, bytes(16)))[-1] == "NWK security"   # wrong key: says so, goes no further


def test_dissect_never_raises_on_cut_frames():
    frame = builders.build_link_status(NET, pan=0x1a62, src=0x6ca5, src64=DEV64, counter=9, neighbours=[(0x0000, 1, 1)])
    for cut in range(len(frame) + 1):
        layers = dissect(frame[:cut], NET)
        assert layers and all(isinstance(l["fields"], list) for l in layers)
    assert dissect(frame, NET)[-1]["layer"] == "NWK command"


def test_a_cut_attribute_value_is_left_out_not_read_from_what_is_there():
    report = bytes([0x18, 0x01, 0x0a])
    whole = report + bytes([0x21, 0x00, 0x20, 0x64]) + bytes([0x20, 0x00, 0x21, 0x10, 0x27])   # battery %, then a uint16
    assert decode.zcl_values(whole) == {0x0021: 100, 0x0020: 10000}
    assert decode.zcl_values(whole[:-1]) == {0x0021: 100}                      # the uint16 lost a byte: not 16, nothing
    assert decode.zcl_values(report + bytes([0x05, 0x00, 0x42, 20]) + b"abc") == {}   # a 20-byte string, 3 bytes there


def test_a_cluster_specific_command_is_not_read_as_attributes():
    # Command 0x0a of a cluster is not Report Attributes: only global commands carry attribute records.
    assert decode.zcl_values(bytes([0x19, 0x01, 0x0a, 0x21, 0x00, 0x20, 0x64])) == {}
    assert decode.zcl_header(bytes([0x1d, 0x0b, 0x10, 0x07, 0x00, 0xaa])) == {
        "fc": 0x1d, "global": False, "manufacturer": 0x100b, "seq": 7, "command": 0, "body": b"\xaa"}
    assert decode.zcl_header(bytes([0x04, 0x0b])) is None


def test_a_frame_cut_inside_a_header_is_not_a_join_nor_a_touchlink_frame():
    join = builders.build_transport_key(crypto.DEFAULT_TC_LINK_KEY, seq=1, pan=0x1a62, mac_dst=0x1234, mac_src=0x0000,
                                        coord64=COORD64, counter=1, network_key=NET)
    assert decode.transport_key_envelope(join) is not None
    assert decode.transport_key_envelope(join[:22]) is None      # cut inside the APS security header
    scan = builders.build_touchlink_scan_response(seq=1, pan=0x1a62, mac_dst=0x0000, mac_src=0x3344, transaction_id=5, response_id=9)
    assert decode.touchlink_scan_response(scan) == (5, 9)
    assert decode.touchlink_scan_response(bytes([scan[0] | 0x08]) + scan[1:]) is None   # MAC security: not readable


def test_dissect_shows_a_green_power_source_id_and_says_why_it_stops():
    layers = dissect(builders.build_gpdf(2, 0x01234567))
    assert dict(layers[-1]["fields"])["GPD source ID"] == "0x01234567"
    reserved = dissect(bytes([0x01, 0x04, 0x00]) + bytes(12))    # destination addressing mode 1 does not exist
    assert reserved[-1]["layer"] == "Not decoded" and dict(reserved[-1]["fields"])["Reason"] == "reserved addressing mode"
    assert dissect(b"\x61")[-1]["layer"] == "Truncated"
