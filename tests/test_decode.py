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


def test_network_payload_round_trips():
    frame = decode.build_secured_nwk(NET, seq=1, pan=0x1a62, mac_dst=0x0000, mac_src=0x1234,
                                     nwk_dst=0x0000, nwk_src=0x1234, radius=30, nwk_seq=1,
                                     src64=DEV64, counter=1, payload=b"hello aps")
    assert decode.decrypt_network_payload(frame, NET) == b"hello aps"
    assert decode.decrypt_network_payload(frame, bytes(16)) is None
