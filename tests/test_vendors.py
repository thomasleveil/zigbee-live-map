from zigbee_live_map import vendors


def test_bundled_snapshot_resolves_prefixes_of_every_length():
    registry = vendors.Registry(None)
    assert registry.meta["origin"] == "bundled" and registry.meta["entries"] > vendors.MIN_ENTRIES
    assert registry.lookup("00:12:4b:00:00:00:00:01") == "Texas Instruments"           # 24-bit block
    assert registry.lookup("70:b3:d5:2b:60:00:00:01") not in (None, vendors.SUBALLOCATED)  # 36-bit block
    assert registry.lookup("02:00:00:ff:fe:00:2b:01") is None                         # not assigned


def test_snapshot_format_round_trips_and_an_update_takes_precedence(tmp_path):
    table = vendors._parse_csv('Registry,Assignment,Organization Name,Organization Address\nMA-L,AABBCC,"Example  Chips, Inc",Somewhere\n')
    assert table == {"AABBCC": "Example Chips, Inc"}
    (tmp_path / vendors.USER_FILE).write_bytes(vendors._encode(table, "2030-01-02"))
    registry = vendors.Registry(tmp_path)
    assert registry.meta == {"date": "2030-01-02", "entries": 1, "origin": "updated"}
    assert registry.lookup("aa:bb:cc:00:00:00:00:01") == "Example Chips, Inc"


def test_unreadable_update_falls_back_to_the_bundled_snapshot(tmp_path):
    (tmp_path / vendors.USER_FILE).write_bytes(b"not gzip")
    assert vendors.Registry(tmp_path).meta["origin"] == "bundled"
